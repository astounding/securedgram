# frozen_string_literal: true
#
# SecureDGram::UDPServer -- Encrypted UDP messaging daemon
#
# Written by Aaron D. Gifford - https://aarongifford.com/
# Copyright (c) 2016 Aaron D. Gifford
# Contributions by Claude Code Opus 4.6 - https://claude.ai/
#
# Usage of the works is permitted provided that this instrument is
# retained with the works, so that any entity that uses the works is
# notified of this instrument.
#
# DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

require 'logger'
require 'socket'
require 'json'
require 'fileutils'
require 'sqlite3'

module SecureDGram
  class UDPServer
    def initialize(options)
      @options = options
      @socket = nil
      @db = nil
      @running = true
      @ack_queue_out = []  ## In-memory queue for ACK replies (fast turnaround)

      ## Expand relative paths to absolute BEFORE daemonize() chdir's to '/':
      target = @options[:log_target]
      unless ['syslog', 'stdout', '-'].include?(target)
        @options[:log_target] = File.expand_path(target)
      end
      @options[:db_path]  = File.expand_path(@options[:db_path])
      @options[:env_file] = File.expand_path(@options[:env_file]) if @options[:env_file]

      @log = create_logger
    end

    def root_init ; @log.info "root_init" unless @log.nil? ; end
    def pre_fork ; @log.info "pre_fork" unless @log.nil? ; end
    def exit_code(code = 0) ; @log.info "exit_code" unless @log.nil? ; return code ; end

    ##
    ## Create a Logger for the configured log destination.
    ##
    ## SECUREDGRAM_LOG values:
    ##   "syslog"  - Syslog::Logger with LOG_DAEMON facility (default)
    ##   "stdout"  - Logger to STDOUT
    ##   otherwise - Logger to the given file path
    ##
    def create_logger
      target = @options[:log_target]

      case target
      when 'syslog'
        require 'syslog/logger'
        log = Syslog::Logger.new('securedgram', Syslog::LOG_DAEMON)
      when 'stdout', '-'
        log = Logger.new(STDOUT)
      else
        log = Logger.new(target)
      end

      log.level = @options[:loglevel]
      log
    end

    ##
    ## (Re)open logs.  Called by DaemonUtils after fork and on HUP.
    ##
    ## For file logging: closes old handle, opens a new one (supports log rotation).
    ## For syslog: returns a fresh Syslog::Logger (syslog handles rotation internally).
    ## For stdout: returns a new Logger on STDOUT.
    ##
    def setup_logging
      @log = create_logger
      return @log
    end

    ##
    ## Reload configuration from .env on HUP signal.
    ##
    ## Hot-reloadable (takes effect immediately):
    ##   - SECUREDGRAM_SECRET         (shared key)
    ##   - SECUREDGRAM_WINDOW         (timestamp replay window)
    ##   - SECUREDGRAM_MAX_RETRIES    (send retry limit)
    ##   - SECUREDGRAM_RETRY_INTERVAL (seconds before retransmitting unACKed)
    ##
    ## Requires full restart (logged as warnings if changed):
    ##   - SECUREDGRAM_LOG         (log destination -- syslog/file/stdout)
    ##   - SECUREDGRAM_ADDRESS     (bind address -- socket already bound)
    ##   - SECUREDGRAM_PORT        (bind port -- socket already bound)
    ##   - SECUREDGRAM_DB          (database path -- open handle, WAL state)
    ##   - SECUREDGRAM_USER        (process already dropped privileges)
    ##   - SECUREDGRAM_PIDFILE     (PID file already written)
    ##
    def reconfig
      @log.warn "reconfig: reloading .env file"

      ## Re-read .env with force-update:
      SecureDGram::EnvLoader.load_dotenv(@options[:env_file], force: true)
      @log.info "reconfig: .env file reloaded"

      ## Hot-reload: secret key
      new_secret = [ENV.fetch('SECUREDGRAM_SECRET', '')].pack('H*')
      if new_secret != @options[:secret]
        @options[:secret] = new_secret
        @log.warn "reconfig: shared secret UPDATED"
      end

      ## Hot-reload: timestamp window
      new_window = ENV.fetch('SECUREDGRAM_WINDOW', '10').to_i
      if new_window != @options[:window]
        @log.warn "reconfig: window changed from #{@options[:window]}s to #{new_window}s"
        @options[:window] = new_window
      end

      ## Hot-reload: max retries
      new_max_retries = ENV.fetch('SECUREDGRAM_MAX_RETRIES', '10').to_i
      if new_max_retries != @options[:max_retries]
        @log.warn "reconfig: max_retries changed from #{@options[:max_retries]} to #{new_max_retries}"
        @options[:max_retries] = new_max_retries
      end

      ## Hot-reload: retry interval
      new_retry_interval = ENV.fetch('SECUREDGRAM_RETRY_INTERVAL', '5').to_i
      if new_retry_interval != @options[:retry_interval]
        @log.warn "reconfig: retry_interval changed from #{@options[:retry_interval]}s to #{new_retry_interval}s"
        @options[:retry_interval] = new_retry_interval
      end

      ## Warn about restart-only parameters if they changed:
      new_log = ENV.fetch('SECUREDGRAM_LOG', 'syslog')
      if new_log != @options[:log_target]
        @log.warn "reconfig: SECUREDGRAM_LOG changed to #{new_log.inspect} but log destination requires RESTART to take effect"
      end

      new_address = ENV.fetch('SECUREDGRAM_ADDRESS', '0.0.0.0')
      if new_address != @options[:address]
        @log.warn "reconfig: SECUREDGRAM_ADDRESS changed to #{new_address.inspect} but bind address requires RESTART to take effect"
      end

      new_port = ENV.fetch('SECUREDGRAM_PORT', '61773').to_i
      if new_port != @options[:port]
        @log.warn "reconfig: SECUREDGRAM_PORT changed to #{new_port} but bind port requires RESTART to take effect"
      end

      new_db_path = ENV.fetch('SECUREDGRAM_DB', @options[:db_path])
      if new_db_path != @options[:db_path]
        @log.warn "reconfig: SECUREDGRAM_DB changed to #{new_db_path.inspect} but database path requires RESTART to take effect"
      end

      new_user = ENV.fetch('SECUREDGRAM_USER', 'nobody')
      if new_user != @options[:user]
        @log.warn "reconfig: SECUREDGRAM_USER changed to #{new_user.inspect} but user requires RESTART to take effect (already dropped privileges)"
      end

      new_pidfile = ENV.fetch('SECUREDGRAM_PIDFILE', 'securedgram.pid')
      if new_pidfile != @options[:pidfile]
        @log.warn "reconfig: SECUREDGRAM_PIDFILE changed to #{new_pidfile.inspect} but PID file requires RESTART to take effect (already written)"
      end

      @log.warn "reconfig: done"
    end

    ##
    ## Initialize the SQLite3 database (called from post_fork, after socket bind)
    ##
    def init_db
      db_path = @options[:db_path]
      @log.info "Opening SQLite3 database at #{db_path.inspect}"
      FileUtils.mkdir_p(File.dirname(db_path))
      @db = SQLite3::Database.new(db_path)
      @db.results_as_hash = true
      @db.busy_timeout = 1000
      @db.execute("PRAGMA journal_mode = WAL")
      @db.execute("PRAGMA synchronous = NORMAL")
      @db.execute("PRAGMA foreign_keys = ON")

      @db.execute_batch(<<~SQL)
        CREATE TABLE IF NOT EXISTS outbound_messages (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          message_id      TEXT,
          dst_addr        TEXT NOT NULL,
          dst_port        INTEGER NOT NULL,
          payload         TEXT NOT NULL,
          state           TEXT NOT NULL DEFAULT 'pending',
          retry_count     INTEGER NOT NULL DEFAULT 0,
          created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
          sent_at         TEXT,
          ack_received_at TEXT,
          last_error      TEXT,
          updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_outbound_message_id ON outbound_messages(message_id);
        CREATE INDEX IF NOT EXISTS idx_outbound_state ON outbound_messages(state);

        CREATE TABLE IF NOT EXISTS inbound_messages (
          id               INTEGER PRIMARY KEY AUTOINCREMENT,
          message_id       TEXT NOT NULL,
          src_addr         TEXT NOT NULL,
          src_port         INTEGER NOT NULL,
          payload          TEXT NOT NULL,
          crypto_timestamp TEXT NOT NULL,
          state            TEXT NOT NULL DEFAULT 'received',
          ack_sent         INTEGER NOT NULL DEFAULT 0,
          read_count       INTEGER NOT NULL DEFAULT 0,
          received_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
          ack_sent_at      TEXT,
          updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_inbound_message_id ON inbound_messages(message_id);
        CREATE INDEX IF NOT EXISTS idx_inbound_state ON inbound_messages(state);
      SQL

      ## Migration: add read_count column if missing (for databases created before this feature):
      begin
        @db.execute("ALTER TABLE inbound_messages ADD COLUMN read_count INTEGER NOT NULL DEFAULT 0")
        @log.info "Migration: added read_count column to inbound_messages"
      rescue SQLite3::SQLException
        ## Column already exists -- expected on non-first runs
      end

      ## Crash recovery: reset messages stuck in transient 'sending' state
      @db.execute("UPDATE outbound_messages SET state = 'pending', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE state = 'sending'")
      if @db.changes > 0
        @log.warn "Crash recovery: reset #{@db.changes} outbound messages from 'sending' back to 'pending'"
      end

      ## Crash recovery: count unACKed 'sent' messages -- these will be retransmitted
      ## by retransmit_unacked on the first main loop iteration
      unacked_sent = @db.get_first_row("SELECT COUNT(*) as cnt FROM outbound_messages WHERE state = 'sent' AND ack_received_at IS NULL")
      unacked_count = unacked_sent ? unacked_sent['cnt'] : 0
      if unacked_count > 0
        @log.warn "Crash recovery: #{unacked_count} outbound messages in 'sent' state awaiting ACK (will retransmit)"
      end

      ## Crash recovery: re-queue ACKs for inbound messages received but not yet ACK'd
      unacked = @db.execute("SELECT message_id, src_addr, src_port FROM inbound_messages WHERE state = 'received'")
      unacked.each do |row|
        @ack_queue_out << { message_id: row['message_id'], dst_addr: row['src_addr'], dst_port: row['src_port'].to_i, tries: 0 }
      end
      if unacked.size > 0
        @log.warn "Crash recovery: re-queued #{unacked.size} ACKs for un-acknowledged inbound messages"
      end

      @log.info "Database initialized (WAL mode, tables ready)"
    end

    ##
    ## Close the database connection
    ##
    def close_db
      if @db
        @log.info "Closing database connection"
        @db.close rescue nil
        @db = nil
      end
    end

    ##
    ## Bind UDP socket and initialize database
    ##
    def post_fork
      begin
        @log.info "Obtaining socket to listen on UDP #{@options[:address]} port #{@options[:port]}"
        @socket = UDPSocket.new
        @log.info "Socket obtained. Binding to UDP #{@options[:address]} port #{@options[:port]}"
        begin
          @socket.bind(@options[:address], @options[:port])
        rescue Errno::EADDRINUSE
          @log.fatal "Port #{@options[:port]} is already in use. Failed to open socket. Terminating."
          exit 1
        end
        server_bound_addr = @socket.addr
        @log.warn "Socket bound to UDP #{server_bound_addr[2]} port #{server_bound_addr[1]}"
      rescue => e
        @log.error("AN EXCEPTION OCCURRED with socket.bind(): #{e.class}: #{e.message}")
        @log.error("*** BACKTRACE ***")
        e.backtrace.each { |bt| @log.error("... " + bt) }
        @log.error("*** END of BACKTRACE ***")
        exit 1
      end

      ## Initialize database after socket is bound:
      begin
        init_db
      rescue => e
        @log.fatal("Failed to initialize database: #{e.class}: #{e.message}")
        e.backtrace.each { |bt| @log.error("... " + bt) }
        exit 1
      end
    end

    ##
    ## Phase 1: Poll DB for pending outbound messages, encrypt, and send
    ##
    def db_send_outbound
      rows = @db.execute(
        "SELECT id, message_id, dst_addr, dst_port, payload, retry_count FROM outbound_messages WHERE state = 'pending' ORDER BY id ASC LIMIT 50"
      )

      rows.each do |row|
        begin
          ## Parse and validate payload JSON:
          payload_json = JSON.parse(row['payload'])
          message_id = row['message_id']

          ## If message_id is NULL, generate one and inject into payload:
          if message_id.nil? || message_id.empty?
            message_id = SecureRandom.hex(12)
            payload_json['message_id'] = message_id
            payload_str = payload_json.to_json
            @db.execute(
              "UPDATE outbound_messages SET message_id = ?, payload = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
              [message_id, payload_str, row['id']]
            )
            @log.info "Generated message_id #{message_id} for outbound row #{row['id']}"
          else
            ## Ensure payload JSON has matching message_id (inject if missing, validate if present):
            if payload_json.key?('message_id')
              unless payload_json['message_id'] == message_id
                @db.execute(
                  "UPDATE outbound_messages SET state = 'send_failed', last_error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
                  ["payload message_id '#{payload_json['message_id']}' does not match row message_id '#{message_id}'", row['id']]
                )
                @log.warn "Outbound #{message_id}: payload message_id mismatch. Marked send_failed."
                next
              end
            else
              payload_json['message_id'] = message_id
            end
            payload_str = payload_json.to_json
          end

          ## Mark as sending (transient state):
          @db.execute(
            "UPDATE outbound_messages SET state = 'sending', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            [row['id']]
          )

          ## Encrypt and send:
          ciphertext = SecureDGram::Crypto.encrypt(@options[:secret], payload_str, Time.now)
          @socket.send(ciphertext, 0, row['dst_addr'], row['dst_port'])

          ## Success:
          @db.execute(
            "UPDATE outbound_messages SET state = 'sent', sent_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            [row['id']]
          )
          @log.info "Outbound message #{message_id} sent to #{row['dst_addr']}:#{row['dst_port']}"

        rescue Errno::EAGAIN, Errno::EWOULDBLOCK
          new_retry = (row['retry_count'] || 0) + 1
          if new_retry > @options[:max_retries]
            @db.execute(
              "UPDATE outbound_messages SET state = 'send_failed', retry_count = ?, last_error = 'max retries exceeded', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
              [new_retry, row['id']]
            )
            @log.warn "Outbound #{row['message_id']}: max retries exceeded."
          else
            @db.execute(
              "UPDATE outbound_messages SET state = 'pending', retry_count = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
              [new_retry, row['id']]
            )
          end

        rescue Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EHOSTUNREACH => e
          @db.execute(
            "UPDATE outbound_messages SET state = 'send_failed', last_error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            ["#{e.class}: #{e.message}", row['id']]
          )
          @log.warn "Outbound #{row['message_id']} send_failed: #{e.class} #{e.message}"

        rescue JSON::ParserError => e
          @db.execute(
            "UPDATE outbound_messages SET state = 'send_failed', last_error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            ["Invalid JSON payload: #{e.message}", row['id']]
          )
          @log.warn "Outbound #{row['message_id']}: invalid JSON payload."
        end
      end
    rescue SQLite3::BusyException => e
      @log.warn "Database busy during outbound send phase: #{e.message}. Will retry next cycle."
    end

    ##
    ## Phase 2: Receive UDP datagrams (non-blocking)
    ##   - ACKs update outbound rows
    ##   - Regular messages are inserted into inbound table + ACK queued
    ##
    def receive_udp
      loop do
        begin
          message, sender_addr = @socket.recvfrom_nonblock(65536)
          plaintext, timestamp = SecureDGram::Crypto.decrypt(@options[:secret], message)
          now = Time.now

          if timestamp > now + @options[:window] || timestamp < now - @options[:window]
            @log.warn "Message from #{sender_addr[3]}:#{sender_addr[1]} rejected: timestamp #{timestamp} outside +-#{@options[:window]}s window (now=#{now})"
            next
          end

          @log.info "DECRYPTED AUTHENTICATED DATA: #{plaintext.inspect} (#{plaintext.size} bytes)"

          json = JSON.parse(plaintext)
          unless json.key?('message_id') && /^[a-f0-9]{24}$/.match(json['message_id'])
            @log.warn "Message from #{sender_addr[3]}:#{sender_addr[1]}: message_id missing or malformed. Ignoring."
            next
          end

          if json['type'] == 'ACK'
            handle_received_ack(json['message_id'])
          else
            handle_received_message(json, sender_addr, timestamp)
          end

        rescue IO::WaitReadable, Errno::EAGAIN, Errno::EWOULDBLOCK
          break  ## No more data available
        rescue RbNaCl::CryptoError => e
          @log.warn "Decryption failed for datagram from #{sender_addr ? sender_addr[3] : 'unknown'}: #{e.message}"
        rescue JSON::ParserError => e
          @log.warn "JSON parse failed for decrypted message: #{e.message}"
        rescue => e
          @log.fatal("EXCEPTION in receive_udp: #{e.class}: #{e.message}")
          e.backtrace.each { |bt| @log.error("... " + bt) }
          break
        end
      end
    end

    ##
    ## Handle a received ACK: correlate with outbound message and update state
    ##
    def handle_received_ack(message_id)
      @db.execute(
        "UPDATE outbound_messages SET state = 'acknowledged', ack_received_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE message_id = ? AND state IN ('sent', 'sending')",
        [message_id]
      )
      if @db.changes > 0
        @log.info "ACK received for outbound message #{message_id}"
      else
        @log.warn "ACK received for unknown or already-acknowledged message #{message_id}"
      end
    rescue SQLite3::BusyException => e
      @log.warn "Database busy during ACK handling for #{message_id}: #{e.message}"
    end

    ##
    ## Handle a received regular message: insert into DB and queue ACK
    ##
    def handle_received_message(json, sender_addr, crypto_timestamp)
      src_addr = sender_addr[3]
      src_port = sender_addr[1]
      message_id = json['message_id']
      payload = json.to_json

      begin
        @db.execute(
          "INSERT INTO inbound_messages (message_id, src_addr, src_port, payload, crypto_timestamp) VALUES (?, ?, ?, ?, ?)",
          [message_id, src_addr, src_port, payload, crypto_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%N')]
        )
        @log.info "Inbound message #{message_id} from #{src_addr}:#{src_port} stored"
      rescue SQLite3::ConstraintException
        ## Duplicate message_id -- likely a retransmission. Skip insert but still ACK.
        @log.warn "Duplicate inbound message_id #{message_id} from #{src_addr}:#{src_port}. Skipping insert, will still ACK."
      end

      ## Queue ACK regardless (sender needs it even for retransmitted messages):
      @ack_queue_out << { message_id: message_id, dst_addr: src_addr, dst_port: src_port, tries: 0 }

    rescue SQLite3::BusyException => e
      @log.warn "Database busy during inbound message handling for #{message_id}: #{e.message}. Queueing ACK anyway."
      @ack_queue_out << { message_id: message_id, dst_addr: sender_addr[3], dst_port: sender_addr[1], tries: 0 }
    end

    ##
    ## Phase 3: Send queued ACKs from in-memory queue
    ##
    def send_acks
      remaining = []

      @ack_queue_out.each do |ack|
        begin
          ack_json = { type: "ACK", message_id: ack[:message_id] }.to_json
          ciphertext = SecureDGram::Crypto.encrypt(@options[:secret], ack_json, Time.now)
          @socket.send(ciphertext, 0, ack[:dst_addr], ack[:dst_port])

          ## ACK sent successfully -- update inbound row:
          @db.execute(
            "UPDATE inbound_messages SET ack_sent = 1, state = 'ack_sent', ack_sent_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE message_id = ?",
            [ack[:message_id]]
          )
          @log.info "ACK sent for inbound message #{ack[:message_id]} to #{ack[:dst_addr]}:#{ack[:dst_port]}"

        rescue Errno::EAGAIN, Errno::EWOULDBLOCK
          ack[:tries] += 1
          if ack[:tries] > @options[:max_retries]
            @db.execute(
              "UPDATE inbound_messages SET state = 'ack_failed', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE message_id = ?",
              [ack[:message_id]]
            ) rescue nil
            @log.warn "ACK for #{ack[:message_id]}: max retries exceeded."
          else
            remaining << ack
          end

        rescue Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EHOSTUNREACH => e
          @db.execute(
            "UPDATE inbound_messages SET state = 'ack_failed', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE message_id = ?",
            [ack[:message_id]]
          ) rescue nil
          @log.warn "ACK for #{ack[:message_id]} failed: #{e.class} #{e.message}"
        end
      end

      @ack_queue_out = remaining
    rescue SQLite3::BusyException => e
      @log.warn "Database busy during ACK send phase: #{e.message}"
    end

    ##
    ## Phase 4: Retransmit unACKed outbound messages
    ##
    ## Messages in state 'sent' with no ACK after retry_interval seconds
    ## are re-encrypted and resent.  retry_count is incremented each time.
    ## Messages exceeding max_retries are marked 'send_failed'.
    ##
    def retransmit_unacked
      interval = @options[:retry_interval]
      rows = @db.execute(
        "SELECT id, message_id, dst_addr, dst_port, payload, retry_count " \
        "FROM outbound_messages " \
        "WHERE state = 'sent' AND ack_received_at IS NULL " \
        "  AND sent_at < strftime('%Y-%m-%dT%H:%M:%f', 'now', ? || ' seconds') " \
        "ORDER BY id ASC LIMIT 50",
        [(-interval).to_s]
      )

      rows.each do |row|
        new_retry = (row['retry_count'] || 0) + 1

        if new_retry > @options[:max_retries]
          @db.execute(
            "UPDATE outbound_messages SET state = 'send_failed', retry_count = ?, last_error = 'max retries exceeded (no ACK)', updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            [new_retry, row['id']]
          )
          @log.warn "Outbound #{row['message_id']}: max retries exceeded (no ACK after #{new_retry - 1} attempts). Marked send_failed."
          next
        end

        begin
          ciphertext = SecureDGram::Crypto.encrypt(@options[:secret], row['payload'], Time.now)
          @socket.send(ciphertext, 0, row['dst_addr'], row['dst_port'])

          @db.execute(
            "UPDATE outbound_messages SET retry_count = ?, sent_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            [new_retry, row['id']]
          )
          @log.info "Outbound #{row['message_id']} retransmit ##{new_retry} to #{row['dst_addr']}:#{row['dst_port']}"

        rescue Errno::EAGAIN, Errno::EWOULDBLOCK
          @log.warn "Outbound #{row['message_id']} retransmit ##{new_retry}: socket busy, will retry next cycle"

        rescue Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EHOSTUNREACH => e
          @db.execute(
            "UPDATE outbound_messages SET state = 'send_failed', retry_count = ?, last_error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id = ?",
            [new_retry, "#{e.class}: #{e.message}", row['id']]
          )
          @log.warn "Outbound #{row['message_id']} retransmit failed: #{e.class} #{e.message}"
        end
      end
    rescue SQLite3::BusyException => e
      @log.warn "Database busy during retransmit phase: #{e.message}. Will retry next cycle."
    end

    ##
    ## Phase 5: Process received messages (application logic stub)
    ##
    def process_inbound
      ## Stub for future application logic.
      ## Could query: SELECT * FROM inbound_messages WHERE state = 'ack_sent' ...
    end

    ##
    ## Main loop: 5 phases per iteration
    ##
    def run
      @log.debug "run() loop..."

      ## Phase 1: Send pending outbound messages from DB
      db_send_outbound

      ## Phase 2: Receive UDP datagrams (ACKs and regular messages)
      receive_udp

      ## Phase 3: Send queued ACKs from memory
      send_acks

      ## Phase 4: Retransmit unACKed outbound messages
      retransmit_unacked

      ## Phase 5: Application logic for received messages (stub)
      process_inbound

      sleep 0.1
      return @running
    rescue => e
      @log.error("Exception in run() loop: #{e.class}: #{e.message}")
      e.backtrace.each { |bt| @log.error("... " + bt) }
      sleep 1  ## Back off on errors to avoid tight loops
      return @running
    end

    def quit(sig)
      @log.warn("Quitting (signal #{sig.inspect} received)")
      @running = false
      close_db
    end
  end
end
