# frozen_string_literal: true
#
# SecureDGram::Crypto -- ChaCha20-Poly1305-IETF AEAD encryption/decryption
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

require 'rbnacl'
require 'securerandom'

module SecureDGram
  module Crypto
    module_function

    ##
    ## Encrypt a plaintext message with a timestamp envelope.
    ##
    ## key       - 32-byte binary symmetric key
    ## plaintext - String to encrypt
    ## timestamp - Time object (nanosecond precision preserved)
    ##
    ## Returns: nonce (12 bytes) || ciphertext+tag
    ##
    def encrypt(key, plaintext, timestamp)
      nonce = SecureRandom.random_bytes(12) ## 12-byte random nonce
      nsec = timestamp.nsec
      timestamp = timestamp.to_i
      timestamp = [timestamp * 1000000000 + nsec].pack("Q>")
      return nonce + RbNaCl::AEAD::ChaCha20Poly1305IETF.new(key).encrypt(nonce, timestamp + plaintext, nil)
    end

    ##
    ## Decrypt a ciphertext message and extract the timestamp.
    ##
    ## key        - 32-byte binary symmetric key
    ## ciphertext - nonce || ciphertext+tag (as produced by encrypt)
    ##
    ## Returns: [plaintext, timestamp] where timestamp is a Time with nanosecond precision
    ##
    ## Raises RbNaCl::LengthError if ciphertext is too short
    ## Raises RbNaCl::CryptoError if decryption/authentication fails
    ##
    def decrypt(key, ciphertext)
      if ciphertext.size < 28  ## 12-byte prepended NONCE and 16-byte tag for zero-byte data is minimum
        raise RbNaCl::LengthError.new("Invalid nonce + ciphertext size #{ciphertext.size}. Expected a minimum of 12 + 16 = 28 bytes.")
      end
      nonce = ciphertext[0..11]
      ciphertext = ciphertext[12..]
      plaintext = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(key).decrypt(nonce, ciphertext, nil)
      timestamp = plaintext[0..7]
      plaintext = plaintext[8..]
      timestamp = timestamp.unpack("Q>").first
      timestamp = Time.at(timestamp / 1000000000, timestamp % 1000000000, :nsec)
      return plaintext, timestamp
    end
  end
end
