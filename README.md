# SecureDGram

Encrypted UDP datagram messaging daemon with SQLite message store.

SecureDGram uses **ChaCha20-Poly1305-IETF AEAD** encryption (via libsodium) with a pre-shared 256-bit key, **timestamp-based replay protection**, and a **SQLite3 WAL-mode** database for persistent message queuing with acknowledgement tracking.

## Installation

### From RubyGems

```bash
gem install securedgram
```

### From Source

```bash
git clone https://github.com/astounding/securedgram.git
cd securedgram
bundle install
```

### System Dependencies

**libsodium** is required by the `rbnacl` gem:

```bash
# macOS
brew install libsodium

# Debian/Ubuntu
sudo apt-get install libsodium-dev

# FreeBSD
pkg install libsodium

# RHEL/CentOS
sudo yum install libsodium-devel
```

## Configuration

### 1. Create your `.env` file

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` with your deployment settings:

```bash
SECUREDGRAM_USER=securedgram
SECUREDGRAM_LOG=syslog
SECUREDGRAM_PIDFILE=securedgram.pid
SECUREDGRAM_ADDRESS=0.0.0.0
SECUREDGRAM_PORT=61773
SECUREDGRAM_SECRET=your_64_char_hex_secret_here
SECUREDGRAM_WINDOW=10
SECUREDGRAM_MAX_RETRIES=10
SECUREDGRAM_RETRY_INTERVAL=5
SECUREDGRAM_DB=securedgram.db
```

### 2. Generate a shared secret

```bash
ruby -e "require 'securerandom'; puts SecureRandom.hex(32)"
```

This produces a 64-character hex string representing 32 random bytes. Place it in `SECUREDGRAM_SECRET` in your `.env` file. The same secret must be configured on both the server and all clients.

### 3. Log destination (`SECUREDGRAM_LOG`)

| Value | Behavior |
|-------|----------|
| `syslog` | Log via syslog with `LOG_DAEMON` facility (default, zero-setup) |
| `stdout` | Log to standard output (useful for foreground debugging) |
| `/path/to/file.log` | Traditional file logging (you must create the directory) |

The default is `syslog`, which works immediately after `gem install` with no directory setup. For file logging, create the directory first:

```bash
sudo mkdir -p /var/log/securedgram
sudo chown securedgram:securedgram /var/log/securedgram
```

### 4. Prepare directories (production)

For production deployments with file logging and standard PID/DB locations:

```bash
# PID directory
sudo mkdir -p /var/run/securedgram
sudo chown securedgram:securedgram /var/run/securedgram

# Database directory
sudo mkdir -p /var/lib/securedgram
sudo chown securedgram:securedgram /var/lib/securedgram
```

Then update `.env`:

```bash
SECUREDGRAM_LOG=/var/log/securedgram/daemon.log
SECUREDGRAM_PIDFILE=/var/run/securedgram/daemon.pid
SECUREDGRAM_DB=/var/lib/securedgram/securedgram.db
```

For development or unprivileged use, the defaults (`securedgram.pid` and `securedgram.db` in the current directory, syslog) work with no directory setup.

## Quick Start — Smoke Test

Run through this to verify everything works end-to-end on a single host. The daemon will send a message to itself and you'll read it back with the CLI tools.

### 1. Create a test `.env`

```bash
cd /path/to/securedgram

cat > .env << 'EOF'
SECUREDGRAM_USER=$USER
SECUREDGRAM_LOG=stdout
SECUREDGRAM_PIDFILE=var/run/securedgram.pid
SECUREDGRAM_ADDRESS=127.0.0.1
SECUREDGRAM_PORT=61773
SECUREDGRAM_WINDOW=10
SECUREDGRAM_MAX_RETRIES=10
SECUREDGRAM_DB=var/db/securedgram.db
EOF

# Generate and append a random secret:
echo "SECUREDGRAM_SECRET=$(ruby -e "require 'securerandom'; puts SecureRandom.hex(32)")" >> .env

# Lock it down:
chmod 600 .env
```

### 2. Create the local directories

```bash
mkdir -p var/log var/run var/db
```

### 3. Start the daemon in debug mode

```bash
securedgram -d start
```

(Or `ruby -Ilib exe/securedgram -d start` from a source checkout.)

You should see `Parent PID ... has spawned daemon PID ...`.

### 4. Send a test message to yourself

```bash
sg-send 127.0.0.1 61773 '{"content":"Hello from SecureDGram!"}'
```

Expected output:

```json
{
  "status": "queued",
  "row_id": 1,
  "message_id": null,
  "dst_addr": "127.0.0.1",
  "dst_port": 61773
}
```

The `message_id` is null because we let the daemon generate one. Within ~100ms the daemon will pick it up, encrypt it, send it to itself, decrypt it, store it, and send an ACK (also to itself).

### 5. Read the received message

```bash
sg-recv
```

You should see the inbound message with state `ack_sent` and the full payload. Running `sg-recv` again will show an empty list (the message was marked as read). Use `-r` to see it again:

```bash
sg-recv -r
```

### 6. Check outbound status

```bash
sg-recv --outbound
```

The outbound message should show state `acknowledged` with both `sent_at` and `ack_received_at` timestamps populated.

### 7. Stop the daemon

```bash
securedgram stop
```

If all of the above worked, your installation is good. Replace the `.env` values with your production settings and you're ready to go.

## Running the Daemon

### Commands

```bash
# Start the daemon
securedgram start

# Stop the daemon
securedgram stop

# Restart the daemon (stop + start)
securedgram restart

# Check if the daemon is running
securedgram status

# Wait for the daemon to stop
securedgram poll
```

### Binding to privileged ports

If you need to bind to a port below 1024, run as root. The daemon will drop privileges to the configured user after binding:

```bash
sudo securedgram start
```

### Command-Line Options

All `.env` / default values can be overridden via CLI flags:

```
Usage: securedgram [options] start|stop|restart|status|poll

Options:
    -v, --verbose                    Enable INFO level logging
    -d, --debug                      Enable DEBUG level logging (very verbose)
    -l, --log TARGET                 Log destination: syslog, stdout, or /path/to/file
    -P, --pidfile PIDFILE            Daemon process ID file
    -p, --port PORT                  UDP listen port number
    -b, --bind IP                    Server bind IP address
    -s, --secret HEX                 32-byte shared secret (64-char hex string)
        --db PATH                    SQLite3 database path
    -w, --window SECS                Timestamp replay window in seconds
    -r, --max-retries N              Max send retries before marking failed
    -u, --user USER                  Unix user to run as after privilege drop
        --retry-interval SECS        Seconds before retransmitting unACKed messages
    -V, --version                    Show version and exit
    -h, --help                       Show this help
```

Example with overrides:

```bash
securedgram -d -p 9999 -b 127.0.0.1 start
```

## Database

SecureDGram uses SQLite3 to persist all messages. The database is created automatically on first start.

### Pre-Creating the Database

If you want to create the database before starting the daemon (e.g., to let external processes insert outbound messages ahead of time), use the provided schema file:

```bash
sqlite3 /path/to/securedgram.db < data/schema.sql
```

This sets up WAL mode, creates both tables, and builds the indexes. The daemon's `CREATE TABLE IF NOT EXISTS` statements are idempotent, so it is safe to start the daemon against a pre-created database.

### Queuing Outbound Messages

External processes can queue messages for sending by inserting rows into the `outbound_messages` table:

```ruby
require 'sqlite3'
require 'json'
require 'securerandom'

db = SQLite3::Database.new('/path/to/securedgram.db')
db.execute("PRAGMA journal_mode = WAL")
db.busy_timeout = 5000

# message_id is optional -- if NULL, the daemon generates one
message_id = SecureRandom.hex(12)
payload = { message_id: message_id, content: "Hello, world!" }.to_json

db.execute(
  "INSERT INTO outbound_messages (message_id, dst_addr, dst_port, payload) VALUES (?, ?, ?, ?)",
  [message_id, "192.168.1.100", 61773, payload]
)
db.close
```

If you omit `message_id` (set it to NULL), the daemon will generate one using `SecureRandom.hex(12)` and inject it into the payload JSON before sending.

### Message States

**Outbound messages** progress through these states:

| State | Meaning |
|-------|---------|
| `pending` | Queued, waiting to be sent |
| `sending` | Transient: daemon is about to send (resets to `pending` on crash) |
| `sent` | Datagram sent, awaiting ACK |
| `acknowledged` | ACK received from remote peer |
| `send_failed` | Terminal failure (network error or max retries) |

**Inbound messages** progress through these states:

| State | Meaning |
|-------|---------|
| `received` | Message stored, ACK not yet sent |
| `ack_sent` | ACK successfully sent back to sender |
| `ack_failed` | ACK sending failed |

### Checking Message Status

```bash
# Check outbound message status
sqlite3 securedgram.db \
  "SELECT message_id, state, sent_at, ack_received_at FROM outbound_messages ORDER BY id DESC LIMIT 10"

# Check received messages
sqlite3 securedgram.db \
  "SELECT message_id, src_addr, state, received_at FROM inbound_messages ORDER BY id DESC LIMIT 10"
```

### Database Concurrency

The database uses WAL (Write-Ahead Logging) mode for concurrent access. External processes that write to the database SHOULD also use WAL mode:

```ruby
db = SQLite3::Database.new('/path/to/securedgram.db')
db.execute("PRAGMA journal_mode = WAL")
db.busy_timeout = 5000  # Wait up to 5 seconds on contention
```

## CLI Tools

SecureDGram includes three command-line tools for interacting with the message database.

### sg-send — Inject Outbound Messages

Queue a message for the daemon to encrypt and send:

```bash
# Basic usage: destination IP, port, JSON payload
sg-send 192.168.1.100 61773 '{"content":"Hello, world!"}'

# With an explicit message_id (24-char hex):
sg-send -m abcdef012345abcdef012345 192.168.1.100 61773 '{"content":"ping"}'

# Read payload from a file:
sg-send --file message.json 192.168.1.100 61773

# Pipe payload from stdin:
echo '{"content":"piped message"}' | sg-send 192.168.1.100 61773 -

# Use a different database path:
sg-send --db /tmp/sg.db 192.168.1.100 61773 '{"content":"test"}'

# Quiet mode (no output, exit code only):
sg-send -q 192.168.1.100 61773 '{"content":"silent"}'
```

On success, outputs a JSON confirmation:

```json
{
  "status": "queued",
  "row_id": 42,
  "message_id": "abcdef012345abcdef012345",
  "dst_addr": "192.168.1.100",
  "dst_port": 61773
}
```

If `message_id` is omitted, the daemon generates one on the next poll cycle.

**Options:**

| Flag | Description |
|------|-------------|
| `--db PATH` | SQLite3 database path (default: from `.env`) |
| `-m`, `--message-id HEX` | Set message_id (24-char hex) |
| `-f`, `--file PATH` | Read JSON payload from file |
| `-q`, `--quiet` | Suppress output on success |
| `-V`, `--version` | Show version |
| `-h`, `--help` | Show help |

### sg-recv — Read Messages

Query inbound (received) or outbound messages from the database. By default, only **unread** inbound messages are shown (those with `read_count = 0`). Displaying a message increments its `read_count`.

```bash
# Show unread inbound messages (default):
sg-recv

# Include already-read messages:
sg-recv -r

# Peek at unread without marking them as read:
sg-recv --no-mark

# Show last 50 unread messages:
sg-recv -n 50

# Filter by state:
sg-recv --state ack_sent

# Filter by sender IP:
sg-recv --from 192.168.1.100

# Look up a specific message (always shown regardless of read state):
sg-recv --id abcdef012345abcdef012345

# Show outbound message status (read_count does not apply):
sg-recv --outbound

# Outbound messages awaiting ACK:
sg-recv --outbound --state sent

# Follow mode (like tail -f, polls for new messages):
sg-recv --follow

# Follow with custom poll interval:
sg-recv --follow --interval 0.5

# Compact JSONL output (one object per line):
sg-recv --compact

# Payload only (just the message content):
sg-recv --payload-only
```

**Options:**

| Flag | Description |
|------|-------------|
| `--db PATH` | SQLite3 database path (default: from `.env`) |
| `-n`, `--limit N` | Number of messages to return (default: 20, 0 = all) |
| `-o`, `--outbound` | Query outbound messages instead of inbound |
| `-s`, `--state STATE` | Filter by state |
| `--from ADDR` | Filter inbound by sender IP |
| `--to ADDR` | Filter outbound by destination IP |
| `-i`, `--id MESSAGE_ID` | Look up by message_id (shown regardless of read state) |
| `-r`, `--read-included` | Include already-read messages (default: unread only) |
| `--no-mark` | Don't increment `read_count` (peek without marking as read) |
| `-f`, `--follow` | Continuously poll for new messages (Ctrl+C to stop) |
| `--interval SECS` | Poll interval for follow mode (default: 1.0) |
| `--since-id ID` | Only show messages with row id greater than ID |
| `-c`, `--compact` | JSONL output (one JSON object per line) |
| `-p`, `--payload-only` | Output only the payload field |
| `-V`, `--version` | Show version |
| `-h`, `--help` | Show help |

### sg-clean — Purge Old Messages

Delete terminal-state messages older than a given age. VACUUM is run after deletion by default to reclaim disk space.

**Age suffixes** (following GNU `sleep` / systemd convention):

| Suffix | Meaning |
|--------|---------|
| `s` | Seconds |
| `m` | Minutes |
| `h` | Hours |
| `d` | Days |
| `w` | Weeks |

```bash
# Purge terminal messages older than 7 days:
sg-clean 7d

# Dry run (preview without deleting):
sg-clean --dry-run 30d

# Only purge send failures older than 24 hours:
sg-clean --state send_failed 24h

# Purge everything before a specific date, skip prompt:
sg-clean --before 2025-01-15 -y

# Only clean inbound, include unread messages:
sg-clean --inbound-only --include-unread 90d

# Skip VACUUM after deletion:
sg-clean --no-vacuum 7d

# Purge ALL states (DANGEROUS -- includes active messages):
sg-clean --all-states 30d
```

Absolute dates use ISO 8601 format (always YYYY-MM-DD ordering):

```bash
sg-clean --before 2025-06-15
sg-clean --before 2025-06-15T14:30:00
```

**What gets purged by default** (terminal states only -- the daemon is never working on these):

| Table | States purged | Extra condition |
|-------|---------------|-----------------|
| `outbound_messages` | `acknowledged`, `send_failed` | -- |
| `inbound_messages` | `ack_sent`, `ack_failed` | `read_count > 0` (unread messages are kept) |

Active states (`pending`, `sending`, `sent`, `received`) are never touched unless `--all-states` is passed.

**Options:**

| Flag | Description |
|------|-------------|
| `--db PATH` | SQLite3 database path (default: from `.env`) |
| `--before DATETIME` | Purge before this date instead of using an age (ISO 8601) |
| `--dry-run` | Preview what would be deleted without deleting |
| `-y`, `--yes` | Skip confirmation prompt (for cron / scripting) |
| `--no-vacuum` | Skip `VACUUM` after deletion |
| `--outbound-only` | Only purge outbound messages |
| `--inbound-only` | Only purge inbound messages |
| `--include-unread` | Also purge unread inbound messages (`read_count = 0`) |
| `-s`, `--state STATE` | Target a specific state only |
| `--all-states` | Purge all states including active (DANGEROUS) |
| `-V`, `--version` | Show version |
| `-h`, `--help` | Show help |

## Sending Messages (Wire Protocol)

Clients must send encrypted UDP datagrams to the server. The message format is:

1. Generate a 12-byte random nonce
2. Pack the current timestamp as an 8-byte big-endian nanosecond epoch
3. Build a JSON payload with at least a `message_id` field (24-char lowercase hex)
4. Prepend the packed timestamp to the JSON string
5. Encrypt with ChaCha20-Poly1305-IETF using the shared key and nonce (no AAD)
6. Send: `nonce || ciphertext` as a single UDP datagram

### Example JSON payload

```json
{
  "message_id": "a1b2c3d4e5f6a1b2c3d4e5f6",
  "content": "Hello, SecureDGram!"
}
```

The `message_id` must be a 24-character lowercase hexadecimal string.

### ACK Response

On successful receipt, the server sends an encrypted ACK back to the sender:

```json
{
  "message_id": "a1b2c3d4e5f6a1b2c3d4e5f6",
  "type": "ACK"
}
```

When the daemon receives an ACK for an outbound message, it updates the outbound row's state to `acknowledged` and sets the `ack_received_at` timestamp.

## Signal Handling

The daemon responds to Unix signals:

| Signal | Behavior |
|---|---|
| `TERM`, `INT`, `QUIT` | Graceful shutdown (closes DB, exits) |
| `HUP` | Re-read `.env`, hot-reload configuration, reopen logs |
| `USR1` | Custom hook (no-op by default) |

```bash
# Graceful stop
kill -TERM $(cat securedgram.pid)

# Reload configuration and reopen logs
kill -HUP $(cat securedgram.pid)
```

### What HUP Reloads

On receiving `HUP`, the daemon re-reads the `.env` file and applies changes:

**Hot-reloaded (immediate effect):**

| Setting | Description |
|---------|-------------|
| `SECUREDGRAM_SECRET` | Shared encryption key (new key used for all subsequent messages) |
| `SECUREDGRAM_WINDOW` | Timestamp replay window (seconds) |
| `SECUREDGRAM_MAX_RETRIES` | Maximum send retry count |
| `SECUREDGRAM_RETRY_INTERVAL` | Seconds before retransmitting unACKed messages |

**Log reopening:** The daemon reopens its log handle on HUP. For file logging, this supports log rotation (rename the file, then `kill -HUP`). For syslog, this is a no-op (syslog handles rotation internally).

**Requires restart (warning logged if changed):**

| Setting | Reason |
|---------|--------|
| `SECUREDGRAM_LOG` | Log destination type (syslog/file/stdout) |
| `SECUREDGRAM_ADDRESS` | Socket already bound |
| `SECUREDGRAM_PORT` | Socket already bound |
| `SECUREDGRAM_DB` | Database handle open, WAL state active |
| `SECUREDGRAM_USER` | Privileges already dropped |
| `SECUREDGRAM_PIDFILE` | PID file already written |

Changed values for restart-only settings are logged as warnings but ignored until the next `restart`.

## FreeBSD rc.d Integration

The daemon's `start/stop/restart/status/poll` commands map directly to FreeBSD's rc.d interface. Create `/usr/local/etc/rc.d/securedgram`:

```sh
#!/bin/sh

# PROVIDE: securedgram
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="securedgram"
rcvar="${name}_enable"

load_rc_config $name

: ${securedgram_enable:="NO"}
: ${securedgram_user:="securedgram"}
: ${securedgram_dir:="/usr/local/etc/securedgram"}
: ${securedgram_pidfile:="/var/run/securedgram/securedgram.pid"}

pidfile="${securedgram_pidfile}"

command="/usr/local/bin/securedgram"
securedgram_chdir="${securedgram_dir}"

start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"

securedgram_start() {
  cd "${securedgram_dir}" && \
    su -m "${securedgram_user}" -c "${command} start"
}

securedgram_stop() {
  cd "${securedgram_dir}" && \
    su -m "${securedgram_user}" -c "${command} stop"
}

securedgram_status() {
  cd "${securedgram_dir}" && \
    su -m "${securedgram_user}" -c "${command} status"
}

run_rc_command "$1"
```

Enable in `/etc/rc.conf`:

```sh
securedgram_enable="YES"
securedgram_user="securedgram"
```

## Development

### Running from source

```bash
ruby -Ilib exe/securedgram -d start
ruby -Ilib exe/sg-send 127.0.0.1 61773 '{"content":"test"}'
ruby -Ilib exe/sg-recv
```

### Running tests

```bash
bundle exec rake test
```

### Building the gem

```bash
gem build securedgram.gemspec
```

## Project Layout

```
securedgram/
  exe/                        Executables (installed by gem)
    securedgram               Main daemon
    sg-send                   Inject outbound messages
    sg-recv                   Read messages
    sg-clean                  Purge old messages
  lib/
    securedgram.rb            Top-level require
    securedgram/
      version.rb              SecureDGram::VERSION
      env_loader.rb           .env file parser
      crypto.rb               ChaCha20-Poly1305 encrypt/decrypt
      daemon_utils.rb         Unix double-fork daemonization
      udp_server.rb           The daemon (UDPServer class)
  data/
    schema.sql                Database schema for manual setup
  test/                       Minitest suite
  .env.example                Configuration template
  securedgram.gemspec         Gem specification
```

## Troubleshooting

### "Port already in use"
Another process is bound to the configured port. Check with:
```bash
lsof -i UDP:61773
```

### "PID file already exists"
A stale PID file from a previous run. Verify no process is running, then remove:
```bash
securedgram status
rm securedgram.pid
```

### "Must be run as root"
You're trying to bind to a port below 1024 without root. Either use a higher port or run with `sudo`.

### Debug mode
For verbose output during development:
```bash
securedgram -d start
```

### Database issues
Check database integrity:
```bash
sqlite3 securedgram.db "PRAGMA integrity_check"
```

Check WAL mode is active:
```bash
sqlite3 securedgram.db "PRAGMA journal_mode"
```

## License

[Fair License](LICENSE) -- see LICENSE file for details.
