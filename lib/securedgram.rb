# frozen_string_literal: true
#
# SecureDGram -- Encrypted UDP datagram messaging daemon
#
# Top-level require file.  Loading this file makes all SecureDGram modules
# available:
#
#   require 'securedgram'
#
#   SecureDGram::VERSION          # => "0.1.0"
#   SecureDGram::Crypto.encrypt   # ChaCha20-Poly1305-IETF AEAD
#   SecureDGram::EnvLoader        # .env file parser
#   SecureDGram::DaemonUtils      # Unix double-fork daemonization
#   SecureDGram::UDPServer        # The daemon itself
#

require_relative 'securedgram/version'
require_relative 'securedgram/env_loader'
require_relative 'securedgram/crypto'
require_relative 'securedgram/daemon_utils'
require_relative 'securedgram/udp_server'
