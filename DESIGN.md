# SecureDGram - Design Document

## Overview

SecureDGram is an encrypted UDP messaging daemon written in Ruby. It listens for incoming UDP datagrams, decrypts and authenticates them using ChaCha20-Poly1305 AEAD encryption with a pre-shared key, validates timestamps to prevent replay attacks, parses the JSON payload, stores messages in a SQLite3 database, and sends encrypted ACK responses back to the sender. External processes can queue outbound messages by inserting rows into the database.

## Architecture

The application is packaged as a Ruby gem with five library modules under `lib/securedgram/` and four executables under `exe/`:

### 1. SecureDGram::DaemonUtils (`lib/securedgram/daemon_utils.rb`)

A general-purpose Unix daemon framework that handles:

- **Double-fork daemonization**: Classic Unix technique to fully detach the process from the controlling terminal. The parent forks, the child calls `setsid`, then forks again. The grandchild becomes the daemon.
- **PID file management**: Creation, reading, and cleanup of PID files to track the running daemon and prevent duplicate instances.
- **Process lifecycle**: Start, stop, restart, status, and poll commands via CLI.
- **Privilege dropping**: When started as root, the daemon performs privileged initialization (e.g., binding to low ports), then drops to a configured unprivileged user.
- **Signal handling**: Traps HUP, QUIT, INT, TERM, and USR1 via a self-pipe pattern (signals write to a pipe, a dedicated thread reads and dispatches). This avoids unsafe operations inside signal handlers. HUP triggers a `.env` re-read, hot-reload of safe parameters (secret, window, max retries), and log reopening.
- **Process title**: Sets the process title via FFI binding to `setproctitle` (FreeBSD/macOS).

The module expects daemon classes to implement a contract:
- `initialize(options)` - Constructor
- `run()` - Main loop iteration; returns `true` to continue, `false` to stop
- `setup_logging()` - (Re)open log files; returns a Logger
- Optional: `root_init`, `pre_fork`, `post_fork`, `quit(signal)`, `reconfig`, `exit_code(code)`

### 2. SecureDGram::Crypto (`lib/securedgram/crypto.rb`)

Two module functions provide the cryptographic envelope:

#### `SecureDGram::Crypto.encrypt(key, plaintext, timestamp)`
1. Generates a 12-byte random nonce
2. Packs the timestamp as a big-endian 64-bit nanosecond epoch value
3. Prepends the packed timestamp to the plaintext
4. Encrypts with ChaCha20-Poly1305-IETF AEAD (no additional authenticated data)
5. Returns: `nonce (12 bytes) || ciphertext+tag`

#### `SecureDGram::Crypto.decrypt(key, ciphertext)`
1. Splits off the 12-byte nonce prefix
2. Decrypts with ChaCha20-Poly1305-IETF AEAD
3. Extracts the 8-byte timestamp prefix from the plaintext
4. Returns: `(plaintext, timestamp)` as a Ruby Time object with nanosecond precision

### 3. SecureDGram::EnvLoader (`lib/securedgram/env_loader.rb`)

Shared `.env` file parser used by the daemon and all CLI tools. Supports:
- Comment lines (starting with `#`) and blank lines
- Stripping of matching surrounding quotes (single or double)
- `||=` semantics by default (existing ENV values preserved)
- `force: true` mode for HUP reload (overwrites existing ENV values)

### 4. SecureDGram::UDPServer (`lib/securedgram/udp_server.rb`)

The daemon implementation that plugs into DaemonUtils.

#### Logging

Supports three log destinations via `SECUREDGRAM_LOG`:
- **`syslog`** (default): Uses `Syslog::Logger` with `LOG_DAEMON` facility. Zero-setup, works immediately after gem install.
- **`stdout`**: Standard `Logger` to STDOUT. Useful for foreground debugging.
- **File path**: Standard `Logger` to the specified file. Supports log rotation via HUP signal (daemon reopens the file handle).

#### Main Loop

The main loop (`run()`) executes four phases per iteration:

**Phase 1 -- `db_send_outbound`**: Polls the `outbound_messages` table for rows with `state = 'pending'`. For each: generates `message_id` if NULL, validates/injects it into the JSON payload, encrypts, and sends via UDP. Updates state to `sent` on success, `send_failed` on error.

**Phase 2 -- `receive_udp`**: Non-blocking `recvfrom_nonblock` loop. For each datagram: decrypts, validates timestamp window, parses JSON. If it's an ACK (`json['type'] == 'ACK'`), updates the corresponding outbound row to `acknowledged`. If it's a regular message, INSERTs into `inbound_messages` and queues an ACK in memory.

**Phase 3 -- `send_acks`**: Processes the in-memory ACK queue (`@ack_queue_out`). Encrypts and sends each ACK, then updates the inbound row to `ack_sent`.

**Phase 4 -- `process_inbound`**: Stub for future application logic.

The loop sleeps 100ms between iterations. All database operations are single auto-commit statements to minimize lock contention.

### 5. SQLite3 Message Store

All messages (inbound and outbound) are persisted in a SQLite3 database. The database uses WAL (Write-Ahead Logging) mode so that external processes can read/write concurrently with the daemon.

#### Outbound Messages Table (`outbound_messages`)

| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER PK | Auto-increment row ID |
| `message_id` | TEXT UNIQUE | 24-char hex ID (nullable -- daemon generates if NULL) |
| `dst_addr` | TEXT | Destination IP address |
| `dst_port` | INTEGER | Destination UDP port |
| `payload` | TEXT | JSON payload to encrypt and send |
| `state` | TEXT | Lifecycle state (see below) |
| `retry_count` | INTEGER | Number of send attempts |
| `created_at` | TEXT | Row creation timestamp (ISO 8601) |
| `sent_at` | TEXT | When successfully sent |
| `ack_received_at` | TEXT | When ACK was received |
| `last_error` | TEXT | Most recent error message |
| `updated_at` | TEXT | Last modification timestamp |

**Outbound state machine:**
```
pending --> sending --> sent --> acknowledged
  |            |
  +------------+--> send_failed
```

#### Inbound Messages Table (`inbound_messages`)

| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER PK | Auto-increment row ID |
| `message_id` | TEXT UNIQUE | 24-char hex ID from sender |
| `src_addr` | TEXT | Sender IP address |
| `src_port` | INTEGER | Sender UDP port |
| `payload` | TEXT | Decrypted JSON payload |
| `crypto_timestamp` | TEXT | Timestamp from encrypted envelope (nanosecond precision) |
| `state` | TEXT | Lifecycle state (see below) |
| `ack_sent` | INTEGER | Boolean flag: 1 if ACK sent |
| `read_count` | INTEGER | Number of times read by `sg-recv` (0 = unread) |
| `received_at` | TEXT | When daemon received the message |
| `ack_sent_at` | TEXT | When ACK was sent |
| `updated_at` | TEXT | Last modification timestamp |

**Inbound state machine:**
```
received --> ack_sent
  |
  +--> ack_failed
```

## Wire Protocol

```
Datagram format (encrypted):
+-------+----------------------------+
| Nonce | Ciphertext + Poly1305 Tag  |
| 12 B  |    variable length         |
+-------+----------------------------+

Plaintext structure (inside ciphertext):
+-----------+-------------------+
| Timestamp | JSON Payload      |
| 8 bytes   | variable length   |
+-----------+-------------------+
```

- **Nonce**: 12 bytes, randomly generated per message
- **Timestamp**: 8-byte big-endian unsigned integer encoding nanosecond-precision Unix epoch
- **JSON Payload**: Must contain at minimum a `message_id` field (24-char lowercase hex)
- **Replay window**: Configurable via `SECUREDGRAM_WINDOW` (default 10 seconds)

## Security Properties

- **Confidentiality**: ChaCha20 stream cipher
- **Integrity + Authentication**: Poly1305 MAC (AEAD construction)
- **Replay protection**: Configurable timestamp validity window
- **Pre-shared key**: 32-byte (256-bit) symmetric key shared between client and server
- **Privilege separation**: Daemon drops from root to an unprivileged user after binding

## Database Concurrency

- **WAL mode**: Readers never block writers; writers never block readers
- **`busy_timeout = 1000ms`**: SQLite retries internally for up to 1 second on contention
- **`synchronous = NORMAL`**: Safe with WAL; durable against application crashes
- **No explicit transactions**: Each statement auto-commits for minimal lock duration
- **BusyException handling**: All DB operations rescue `SQLite3::BusyException`, log a warning, and skip to the next cycle (retry in ~100ms)
- External processes SHOULD also use WAL mode and set `busy_timeout`

## Crash Recovery

On startup (`init_db`), the daemon performs two recovery operations:

1. **Stuck outbound messages**: Any rows with `state = 'sending'` (transient state from a previous crash) are reset to `pending` for re-send.
2. **Un-ACKed inbound messages**: Any rows with `state = 'received'` (message stored but ACK never sent) are re-queued for ACK sending.

## Configuration

All settings are loaded from environment variables, populated from a `.env` file at startup. On `HUP` signal, the `.env` file is re-read and hot-reloadable parameters take effect immediately:

| Variable | Purpose | Default | HUP Reload |
|---|---|---|---|
| `SECUREDGRAM_USER` | Unix user to run as after privilege drop | `nobody` | Restart only |
| `SECUREDGRAM_LOG` | Log destination (syslog, stdout, or file path) | `syslog` | Restart only (reopens handle) |
| `SECUREDGRAM_PIDFILE` | Path to the PID file | `securedgram.pid` | Restart only |
| `SECUREDGRAM_ADDRESS` | UDP bind address | `0.0.0.0` | Restart only |
| `SECUREDGRAM_PORT` | UDP listen port | `61773` | Restart only |
| `SECUREDGRAM_SECRET` | 32-byte pre-shared key (64 hex chars) | (empty) | Hot-reload |
| `SECUREDGRAM_WINDOW` | Timestamp validity window (seconds) | `10` | Hot-reload |
| `SECUREDGRAM_MAX_RETRIES` | Max send retries before marking failed | `10` | Hot-reload |
| `SECUREDGRAM_RETRY_INTERVAL` | Seconds before retransmitting unACKed message | `5` | Hot-reload |
| `SECUREDGRAM_DB` | SQLite3 database file path | `securedgram.db` | Restart only |

All values can also be overridden via CLI flags (see `--help`).

**Hot-reload** parameters are applied immediately when the daemon receives a HUP signal. **Restart only** parameters are logged as warnings if changed but require a full `stop`/`start` cycle to take effect (the bound socket, open database handle, or dropped privileges cannot be changed in-place). Log handles are reopened on HUP regardless (supports log rotation for file logging).

## Dependencies

| Gem | Purpose |
|---|---|
| `rbnacl` | Libsodium bindings for ChaCha20-Poly1305 AEAD |
| `ffi` | Foreign function interface (used for `setproctitle` and by rbnacl) |
| `sqlite3` | SQLite3 database bindings |
| `json` | JSON parsing (stdlib) |
| `logger` | Logging (stdlib) |
| `syslog/logger` | Syslog logging (stdlib) |

System dependencies: **libsodium** and **sqlite3** must be installed.

## Process Lifecycle

```
CLI: securedgram start
        |
        v
  [Parse options & .env]
        |
        v
  [Check PID file - is daemon already running?]
        |
        v
  [DaemonUtils.daemonize()]
        |
    fork (1st)
        |
        v
    setsid + fork (2nd)
        |
        v
    [Redirect stdio to /dev/null]
        |
        v
    [root_init - privileged setup]
        |
        v
    [Drop privileges to configured user]
        |
        v
    [Setup signal handler thread]
        |
        v
    [post_fork]
      |-- Bind UDP socket
      |-- Open SQLite3 database (WAL mode)
      |-- Create tables if not exist
      |-- Crash recovery (reset stuck states, re-queue ACKs)
        |
        v
    [Main loop (4 phases per iteration)]
      Phase 1: Poll DB -> encrypt -> send outbound
      Phase 2: Receive UDP -> decrypt -> store inbound / handle ACKs
      Phase 3: Send ACKs from memory -> update DB
      Phase 4: Application logic (stub)
        |
        v
    [Signal TERM/INT/QUIT -> close DB -> clean shutdown]
```

## Gem Structure

```
lib/
  securedgram.rb                 Top-level require (loads all modules)
  securedgram/
    version.rb                   SecureDGram::VERSION constant
    env_loader.rb                SecureDGram::EnvLoader (.env parser)
    crypto.rb                    SecureDGram::Crypto (encrypt/decrypt)
    daemon_utils.rb              SecureDGram::DaemonUtils (double-fork, signals, PID)
    udp_server.rb                SecureDGram::UDPServer (the daemon)
exe/
    securedgram                  Main daemon CLI
    sg-send                      Inject outbound messages
    sg-recv                      Read messages from DB
    sg-clean                     Purge old messages
data/
    schema.sql                   Database schema for manual creation
test/
    test_helper.rb               Minitest setup
    test_crypto.rb               Encrypt/decrypt round-trip tests
    test_env_loader.rb           .env parsing edge-case tests
```

## Known Limitations / Notes

- The receive loop uses `recvfrom_nonblock` with a 100ms sleep between poll cycles.
- The `simple_daemonize` method in DaemonUtils exists but is not used by SecureDGram.
- The sys-proctable gem is optional; the code falls back to `ps` for process name validation.
- ACKs use an in-memory queue (`@ack_queue_out`) for fast turnaround. If the daemon crashes between receiving a message and sending its ACK, the ACK is re-queued from the DB on restart.
- The `process_inbound` method is a stub for future application logic.
- `Syslog::Logger` is not available on Windows (POSIX only). File and stdout logging work on all platforms.
