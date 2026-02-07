# frozen_string_literal: true

require_relative "test_helper"

class TestCrypto < Minitest::Test
  def setup
    @key = SecureRandom.random_bytes(32)
  end

  ## --- Round-trip tests ---

  def test_encrypt_decrypt_round_trip
    plaintext = "Hello, SecureDGram!"
    timestamp = Time.now

    ciphertext = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)
    decrypted_text, decrypted_time = SecureDGram::Crypto.decrypt(@key, ciphertext)

    assert_equal plaintext, decrypted_text
    # Compare nanosecond epoch to avoid floating-point rounding:
    assert_equal timestamp.to_i, decrypted_time.to_i
    assert_equal timestamp.nsec, decrypted_time.nsec
  end

  def test_round_trip_empty_plaintext
    plaintext = ""
    timestamp = Time.now

    ciphertext = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)
    decrypted_text, decrypted_time = SecureDGram::Crypto.decrypt(@key, ciphertext)

    assert_equal plaintext, decrypted_text
    assert_equal timestamp.to_i, decrypted_time.to_i
  end

  def test_round_trip_binary_data
    plaintext = (0..255).map(&:chr).join  # All byte values
    timestamp = Time.now

    ciphertext = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)
    decrypted_text, _ = SecureDGram::Crypto.decrypt(@key, ciphertext)

    assert_equal plaintext.b, decrypted_text.b
  end

  def test_round_trip_json_payload
    payload = { "message_id" => "abcdef012345abcdef012345", "content" => "test" }
    plaintext = JSON.generate(payload)
    timestamp = Time.now

    ciphertext = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)
    decrypted_text, _ = SecureDGram::Crypto.decrypt(@key, ciphertext)
    decrypted_json = JSON.parse(decrypted_text)

    assert_equal payload, decrypted_json
  end

  def test_round_trip_preserves_nanosecond_precision
    # Use a timestamp with known nanoseconds:
    timestamp = Time.at(1700000000, 123456789, :nsec)

    ciphertext = SecureDGram::Crypto.encrypt(@key, "test", timestamp)
    _, decrypted_time = SecureDGram::Crypto.decrypt(@key, ciphertext)

    assert_equal 123456789, decrypted_time.nsec
    assert_equal 1700000000, decrypted_time.to_i
  end

  ## --- Ciphertext structure tests ---

  def test_ciphertext_has_nonce_prefix
    ciphertext = SecureDGram::Crypto.encrypt(@key, "test", Time.now)

    # Minimum size: 12 (nonce) + 8 (timestamp) + 4 (plaintext "test") + 16 (tag) = 40
    assert ciphertext.size >= 40, "Ciphertext too short: #{ciphertext.size} bytes"
  end

  def test_different_nonces_each_time
    plaintext = "same message"
    timestamp = Time.now

    ct1 = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)
    ct2 = SecureDGram::Crypto.encrypt(@key, plaintext, timestamp)

    # Nonces (first 12 bytes) should differ:
    refute_equal ct1[0..11], ct2[0..11], "Two encryptions produced the same nonce"
    # Full ciphertexts should also differ:
    refute_equal ct1, ct2, "Two encryptions produced identical ciphertext"
  end

  ## --- Error handling tests ---

  def test_wrong_key_fails_decryption
    ciphertext = SecureDGram::Crypto.encrypt(@key, "secret data", Time.now)
    wrong_key = SecureRandom.random_bytes(32)

    assert_raises(RbNaCl::CryptoError) do
      SecureDGram::Crypto.decrypt(wrong_key, ciphertext)
    end
  end

  def test_tampered_ciphertext_fails
    ciphertext = SecureDGram::Crypto.encrypt(@key, "integrity check", Time.now)

    # Flip a bit in the ciphertext body (after nonce):
    tampered = ciphertext.dup
    tampered[20] = (tampered[20].ord ^ 0x01).chr

    assert_raises(RbNaCl::CryptoError) do
      SecureDGram::Crypto.decrypt(@key, tampered)
    end
  end

  def test_truncated_ciphertext_raises_length_error
    assert_raises(RbNaCl::LengthError) do
      SecureDGram::Crypto.decrypt(@key, "too short")
    end
  end

  def test_empty_ciphertext_raises_length_error
    assert_raises(RbNaCl::LengthError) do
      SecureDGram::Crypto.decrypt(@key, "")
    end
  end

  def test_minimum_length_ciphertext_27_bytes_raises
    # 27 bytes is one short of the minimum (12 nonce + 16 tag = 28)
    assert_raises(RbNaCl::LengthError) do
      SecureDGram::Crypto.decrypt(@key, SecureRandom.random_bytes(27))
    end
  end
end
