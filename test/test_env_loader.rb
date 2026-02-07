# frozen_string_literal: true

require_relative "test_helper"
require "tempfile"

class TestEnvLoader < Minitest::Test
  def setup
    # Save original ENV state for keys we'll test with:
    @saved_env = {}
  end

  def teardown
    # Restore ENV:
    @saved_env.each do |key, value|
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end
  end

  ## Save an ENV key so we can restore it in teardown:
  def save_env(key)
    @saved_env[key] = ENV[key] unless @saved_env.key?(key)
  end

  ## Create a temp .env file with the given content, yield its path, then clean up:
  def with_env_file(content)
    file = Tempfile.new(['.env', ''])
    file.write(content)
    file.close
    yield file.path
  ensure
    file.unlink if file
  end

  ## --- Basic parsing ---

  def test_loads_simple_key_value
    save_env('TEST_ENVLOADER_SIMPLE')
    ENV.delete('TEST_ENVLOADER_SIMPLE')

    with_env_file("TEST_ENVLOADER_SIMPLE=hello") do |path|
      result = SecureDGram::EnvLoader.load_dotenv(path)
      assert result, "load_dotenv should return true"
      assert_equal "hello", ENV['TEST_ENVLOADER_SIMPLE']
    end
  end

  def test_strips_double_quotes
    save_env('TEST_ENVLOADER_DQ')
    ENV.delete('TEST_ENVLOADER_DQ')

    with_env_file('TEST_ENVLOADER_DQ="quoted value"') do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "quoted value", ENV['TEST_ENVLOADER_DQ']
    end
  end

  def test_strips_single_quotes
    save_env('TEST_ENVLOADER_SQ')
    ENV.delete('TEST_ENVLOADER_SQ')

    with_env_file("TEST_ENVLOADER_SQ='single quoted'") do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "single quoted", ENV['TEST_ENVLOADER_SQ']
    end
  end

  def test_preserves_inner_quotes
    save_env('TEST_ENVLOADER_INNER')
    ENV.delete('TEST_ENVLOADER_INNER')

    with_env_file("TEST_ENVLOADER_INNER=he said \"hello\"") do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal 'he said "hello"', ENV['TEST_ENVLOADER_INNER']
    end
  end

  def test_skips_comments
    save_env('TEST_ENVLOADER_COMMENT')
    ENV.delete('TEST_ENVLOADER_COMMENT')

    content = <<~ENV
      # This is a comment
      TEST_ENVLOADER_COMMENT=value
      # Another comment
    ENV

    with_env_file(content) do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "value", ENV['TEST_ENVLOADER_COMMENT']
    end
  end

  def test_skips_blank_lines
    save_env('TEST_ENVLOADER_BLANK')
    ENV.delete('TEST_ENVLOADER_BLANK')

    content = <<~ENV

      TEST_ENVLOADER_BLANK=works

    ENV

    with_env_file(content) do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "works", ENV['TEST_ENVLOADER_BLANK']
    end
  end

  def test_handles_equals_in_value
    save_env('TEST_ENVLOADER_EQ')
    ENV.delete('TEST_ENVLOADER_EQ')

    with_env_file("TEST_ENVLOADER_EQ=a=b=c") do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "a=b=c", ENV['TEST_ENVLOADER_EQ']
    end
  end

  ## --- Force mode ---

  def test_does_not_overwrite_existing_by_default
    save_env('TEST_ENVLOADER_NOFORCE')
    ENV['TEST_ENVLOADER_NOFORCE'] = 'original'

    with_env_file("TEST_ENVLOADER_NOFORCE=new") do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "original", ENV['TEST_ENVLOADER_NOFORCE']
    end
  end

  def test_force_overwrites_existing
    save_env('TEST_ENVLOADER_FORCE')
    ENV['TEST_ENVLOADER_FORCE'] = 'original'

    with_env_file("TEST_ENVLOADER_FORCE=forced") do |path|
      SecureDGram::EnvLoader.load_dotenv(path, force: true)
      assert_equal "forced", ENV['TEST_ENVLOADER_FORCE']
    end
  end

  ## --- Missing file ---

  def test_returns_false_for_missing_file
    result = SecureDGram::EnvLoader.load_dotenv("/nonexistent/path/.env")
    refute result, "load_dotenv should return false for missing file"
  end

  ## --- Multiple keys ---

  def test_loads_multiple_keys
    save_env('TEST_ENVLOADER_A')
    save_env('TEST_ENVLOADER_B')
    save_env('TEST_ENVLOADER_C')
    ENV.delete('TEST_ENVLOADER_A')
    ENV.delete('TEST_ENVLOADER_B')
    ENV.delete('TEST_ENVLOADER_C')

    content = <<~ENV
      TEST_ENVLOADER_A=alpha
      TEST_ENVLOADER_B=bravo
      TEST_ENVLOADER_C=charlie
    ENV

    with_env_file(content) do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "alpha",   ENV['TEST_ENVLOADER_A']
      assert_equal "bravo",   ENV['TEST_ENVLOADER_B']
      assert_equal "charlie", ENV['TEST_ENVLOADER_C']
    end
  end

  ## --- Whitespace handling ---

  def test_strips_key_and_value_whitespace
    save_env('TEST_ENVLOADER_WS')
    ENV.delete('TEST_ENVLOADER_WS')

    with_env_file("  TEST_ENVLOADER_WS  =  padded  ") do |path|
      SecureDGram::EnvLoader.load_dotenv(path)
      assert_equal "padded", ENV['TEST_ENVLOADER_WS']
    end
  end
end
