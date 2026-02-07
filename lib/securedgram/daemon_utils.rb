# frozen_string_literal: true
#
# SecureDGram::DaemonUtils -- Unix daemonization framework
#
# Written by Aaron D. Gifford - https://aarongifford.com/
# Contributions by Claude Code Opus 4.6 - https://claude.ai/
# Copyright (c) InfoWest, Inc.
#
# Usage of the works is permitted provided that this instrument is
# retained with the works, so that any entity that uses the works
# is notified of this instrument.
#
# DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

require 'etc'
require 'ffi'
require 'fileutils'

module SecureDGram
  module DaemonUtils
    ## FFI binding for setproctitle (FreeBSD/macOS)
    module LibC
      extend FFI::Library
      ffi_lib 'libc'
      attach_function :setproctitle, [:string, :varargs], :void
    rescue LoadError
      # setproctitle not available on this platform
    end

    ##
    ## Read PID from a PID file
    ##
    def self.get_pid_from_file(pidfile)
      return nil unless File.file?(pidfile)
      File.read(pidfile).strip.to_i
    rescue
      nil
    end

    ##
    ## Write PID to a PID file
    ##
    def self.write_pidfile(pidfile, pid = Process.pid)
      FileUtils.mkdir_p(File.dirname(pidfile))
      File.open(pidfile, File::RDWR|File::CREAT|File::EXCL, 0600) do |pf|
        pf.write(pid.to_s)
      end
    rescue Errno::EEXIST
      # PID file already exists
      raise "PID file #{pidfile} already exists"
    end

    ##
    ## Remove PID file
    ##
    def self.remove_pidfile(pidfile)
      File.delete(pidfile) if File.file?(pidfile)
    end

    ##
    ## Check if a process is running by PID
    ##
    def self.process_running?(pid)
      return false if pid.nil? || pid <= 0

      begin
        Process.kill(0, pid)
        return true
      rescue Errno::ESRCH
        # Process doesn't exist
        return false
      rescue Errno::EPERM
        # Process exists but we don't have permission (still running)
        return true
      end
    end

    ##
    ## Get the command line of a process by PID using ps (works on macOS/FreeBSD/Linux)
    ##
    def self.get_process_cmdline(pid)
      `ps -p #{pid} -o command= 2>/dev/null`.strip
    rescue
      nil
    end

    ##
    ## Is a PID running a valid process or not?
    ##
    def self.is_pid_running(pid, prog_name = nil)
      return false if pid.nil? || pid == 0

      if process_running?(pid)
        # Optionally validate process name
        if prog_name
          begin
            require 'sys-proctable'
            psinfo = Sys::ProcTable.ps(pid: pid)
            if psinfo && !psinfo.cmdline.include?(prog_name)
              STDERR.puts "WARNING: Process #{pid} is running but cmdline doesn't match: #{psinfo.cmdline.inspect}"
              return false
            end
          rescue LoadError
            # sys-proctable not available, fall back to ps command
            cmdline = get_process_cmdline(pid)
            if cmdline && !cmdline.empty? && !cmdline.include?(prog_name)
              STDERR.puts "WARNING: Process #{pid} is running but cmdline doesn't match: #{cmdline.inspect}"
              return false
            end
          end
        end
        return true
      end

      # Process not running:
      return false
    end

    ##
    ## Return the PID of a running daemon OR nil if not running
    ## Optionally validates the process command line matches prog_name
    ##
    def self.running_pid(pidfile, prog_name = nil)
      pid = get_pid_from_file(pidfile)
      return pid if is_pid_running(pid, prog_name)
      # Process not running, clean up stale PID file
      remove_pidfile(pidfile)
      return nil
    end

    ##
    ## Stop a running process by PID
    ##
    def self.stop_process(pid, prog_name)
      return true unless is_pid_running(pid, prog_name) # Already stopped

      # Try sending a sequence of signals to terminate the process gracefully,
      # finally resorting to KILL.
      ['TERM', 'INT', 'KILL', 'KILL'].each_with_index do |signal, index|
        # Check if the process has terminated between signals
        return true unless is_pid_running(pid, prog_name)

        begin
          Process.kill(signal, pid)
        rescue Errno::ESRCH
          # Process ceased to exist between the check and the kill, which is success.
          return true
        end

        # Wait for the process to die. Wait longer for graceful signals.
        sleep(signal == 'KILL' ? 1 : 2)
      end

      # Final check to see if the process is still running after all our attempts
      if is_pid_running(pid, prog_name)
        STDERR.puts "Failed to terminate process PID #{pid} with signals. Please terminate it manually."
        return false
      end

      # If we've reached here, the process is no longer running.
      return true
    end

    ##
    ## Stop a running daemon process
    ##
    def self.stop_daemon(pidfile, prog_name = nil)
      pid = get_pid_from_file(pidfile)
      if pid.nil? || pid == 0
        STDERR.puts "Unable to read PID from file #{pidfile.inspect}"
        return false
      end

      oldpid = pid
      pid = running_pid(pidfile, prog_name)
      if pid.nil?  # Already stopped
        STDERR.puts "Process (PID #{oldpid}) doesn't exist."
        remove_pidfile(pidfile)
        return true
      end

      ## Try killing the process:
      is_stopped = stop_process(pid, prog_name)

      if is_stopped
        ## Check to see if there's a new replacement process:
        pid = running_pid(pidfile, prog_name)
        if !pid.nil?
          if pid == oldpid
            STDERR.puts "Process (PID #{oldpid}) has been stopped ALLEGEDLY, but there's a RUNNING process (PID #{pid}) with the SAME PID still running."
            return false
          end
          STDERR.puts "Process (PID #{oldpid}) has been stopped. NOTE that a NEW process (PID #{pid}) has since started."
          return false  ## Process was stopped, but daemon is still running.
        end
        STDERR.puts "Process (PID #{oldpid}) has been stopped."
        remove_pidfile(pidfile)
        return true
      end
      STDERR.puts "Failed to stop process (PID #{oldpid})!"
      return false
    end

    ##
    ## Poll - wait for a daemon to stop
    ##
    def self.poll_daemon(pidfile, prog_name = nil)
      pid = running_pid(pidfile, prog_name)
      while !pid.nil?
        sleep 0.1
        pid = running_pid(pidfile, prog_name)
      end
    end

    ##
    ## Daemonize a process using double-fork
    ##
    ## klass: A class that responds to:
    ##   - initialize(options) - constructor
    ##   - run() - main loop (returns true to continue, false to stop)
    ##   - root_init() - operations requiring root privileges (optional)
    ##   - pre_fork() - called before forking (optional)
    ##   - post_fork() - called after forking in child (optional)
    ##   - quit() - called on shutdown signals (optional)
    ##   - reconfig() - called on HUP signal (optional)
    ##   - exit_code(code) - called to get exit code (optional)
    ##   - setup_logging()  - called to re-open logs (after fork/daemonization) - returns a logging object
    ##
    ## options: Hash of options to pass to klass.new
    ##   Must include :log Logger object to log to
    ##   Must include :prog_name for process title
    ##   Must include :user for dropping privileges
    ##    which takes as first argument the instance of the klass,
    ##    an optional hash of options, and an optional logger object
    ##
    def self.daemonize(klass, options)
      prog_name = options[:prog_name] or raise "Missing :prog_name in options"
      daemon_user = options[:user] or raise "Missing :user in options"
      log = options[:log] or raise "Missing :log in options"

      # Create daemon instance
      daemon = klass.new(options)

      # Pre-fork hook
      daemon.pre_fork if daemon.respond_to?(:pre_fork)

      parent_pid = Process.pid
      read_pid, write_pid = IO.pipe

      Process.fork do
        ## Child (soon to be a daemon) process:
        read_pid.close

        ## Set session ID:
        Process.setsid

        ## Fork again (parent exits):
        exit 0 if Process.fork

        ## Tell parent the daemon PID:
        write_pid.write(Process.pid.to_s)
        write_pid.close

        ## Make working directory the root:
        Dir.chdir('/')

        ## Clear file creation mask:
        File.umask(0)

        ## Reroute standard I/O:
        STDIN.reopen('/dev/null')
        STDOUT.reopen('/dev/null', 'a')
        STDERR.reopen(STDOUT)

        ## Start child process logging initially:
        log = daemon.setup_logging

        ## Set proctitle (if available)
        begin
          LibC.setproctitle(prog_name) if defined?(LibC)
        rescue
          # setproctitle not available
        end

        log.info("Child daemon PID #{Process.pid} is initializing (parent PID #{parent_pid}) at #{Time.now}")

        ## Perform any operations requiring root privileges:
        begin
          daemon.root_init if daemon.respond_to?(:root_init)
        rescue => e
          log.error("AN EXCEPTION OCCURRED: #{e.class}: #{e.message}")
          log.error("*** BACKTRACE ***")
          e.backtrace.each { |bt| log.error("... " + bt) }
          log.error("*** END of BACKTRACE ***")
          exit 1
        end

        ## Drop privileges (only if running as root):
        user_info = Etc.getpwnam(daemon_user)
        if Process.euid == 0
          log.info("Daemon initialized. Dropping privileges to #{daemon_user}.")
          Process::Sys.setgid(user_info.gid)
          Process::Sys.setuid(user_info.uid)
          log.info("Privileges dropped. Running as user #{daemon_user} GID #{user_info.gid} UID #{user_info.uid}")
        elsif Process.euid == user_info.uid && Process.egid == user_info.gid
          log.info("Already running as user #{daemon_user} (UID #{user_info.uid}, GID #{user_info.gid})")
        else
          current_user = Etc.getpwuid(Process.euid).name
          log.warn("WARNING: Running as user #{current_user} (UID #{Process.euid}), expected #{daemon_user} (UID #{user_info.uid})")
        end

        ## Restart logging with dropped privileges:
        oldlog = log
        begin
          log = daemon.setup_logging
        rescue => e
          oldlog.error("AN EXCEPTION OCCURRED: #{e.class}: #{e.message}")
          oldlog.error("*** BACKTRACE ***")
          e.backtrace.each { |bt| oldlog.error("... " + bt) }
          oldlog.error("*** END of BACKTRACE ***")
        end
        oldlog.warn("Logging stopped.")
        oldlog.close if oldlog.respond_to?(:close)
        log.warn("Logging (re)started.")

        ## Setup signal handling:
        log.info("Trapping HUP/QUIT/INT/TERM/USR1 signals.")
        read_sig, write_sig = IO.pipe
        ['HUP', 'QUIT', 'INT', 'TERM', 'USR1'].each do |sig|
          Signal.trap(sig) do
            write_sig.write(sig[0])
            write_sig.flush
          end
        end

        Thread.new do
          log.warn("Signal dispatch thread launched")
          while (buf = read_sig.read(1))
            next unless 'HQITU'.include?(buf)
            sig = case buf
                  when 'H' then 'HUP'
                  when 'Q' then 'QUIT'
                  when 'I' then 'INT'
                  when 'T' then 'TERM'
                  when 'U' then 'USR1'
                  end
            log.warn("Daemon received signal #{sig}")
            if ['TERM', 'INT', 'QUIT'].include?(sig)
              log.warn("Daemon exiting (#{sig} signal received)")
              daemon.quit(sig) if daemon.respond_to?(:quit)
              exit_code = daemon.respond_to?(:exit_code) ? daemon.exit_code(0) : 0
              exit(exit_code)
            elsif sig == 'HUP'
              log.warn("Reopening logs / reloading configuration (HUP signal received)")
              log = daemon.setup_logging
              daemon.reconfig if daemon.respond_to?(:reconfig)
              log.warn("Configuration reloaded")
            elsif sig == 'USR1'
              log.warn("USR1 signal received")
              daemon.usr1() if daemon.respond_to?(:usr1)
            else
              log.error("Unknown signal #{sig.inspect} ignored")
            end
          end
        end
        ## Post-fork hook:
        daemon.post_fork if daemon.respond_to?(:post_fork)

        ## Execute daemon loop:
        begin
          while daemon.run
            # The signal handling thread now manages signals, so the main loop doesn't need to.
          end
        rescue => e
          log.error("AN EXCEPTION OCCURRED: #{e.class}: #{e.message}")
          log.error("*** BACKTRACE ***")
          e.backtrace.each { |bt| log.error("... " + bt) }
          log.error("*** END of BACKTRACE ***")
        end

        ## Terminate:
        log.warn("Daemon main loop ended.")
        exit_code = daemon.respond_to?(:exit_code) ? daemon.exit_code(0) : 0
        exit(exit_code)
      end

      ## Parent process:
      write_pid.close
      daemon_pid = read_pid.read.to_i
      read_pid.close
      STDERR.puts "Parent PID #{parent_pid} has spawned daemon PID #{daemon_pid}"
      return daemon_pid
    end

    ##
    ## Simple daemonize without privilege dropping (for non-root daemons)
    ##
    def self.simple_daemonize(working_dir = '/')
      # First fork
      exit if Process.fork

      # Become session leader
      Process.setsid

      # Second fork
      exit if Process.fork

      # Change working directory
      Dir.chdir(working_dir)

      # Clear file creation mask
      File.umask(0)

      # Close file descriptors
      STDIN.reopen('/dev/null')
      STDOUT.reopen('/dev/null', 'a')
      STDERR.reopen(STDOUT)
    end
  end
end
