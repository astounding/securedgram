# frozen_string_literal: true

require_relative "lib/securedgram/version"

Gem::Specification.new do |spec|
  spec.name          = "securedgram"
  spec.version       = SecureDGram::VERSION
  spec.authors       = ["Aaron D. Gifford"]
  spec.email         = []

  spec.summary       = "Encrypted UDP datagram messaging daemon with SQLite message store"
  spec.description   = "SecureDGram is a ChaCha20-Poly1305 encrypted UDP messaging " \
                        "daemon with SQLite3-backed message queuing, ACK tracking, " \
                        "replay protection, and CLI tools for sending, receiving, " \
                        "and purging messages."
  spec.homepage      = "https://github.com/astounding/securedgram"
  spec.license       = "Fair"

  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata = {
    "homepage_uri"    => spec.homepage,
    "source_code_uri" => "https://github.com/astounding/securedgram",
    "bug_tracker_uri" => "https://github.com/astounding/securedgram/issues",
  }

  spec.files         = Dir[
    "lib/**/*.rb",
    "exe/*",
    "data/*",
    "LICENSE",
    "README.md",
    "DESIGN.md",
    "SECURITY.md",
    "CONTRIBUTORS",
    ".env.example",
  ]
  spec.bindir        = "exe"
  spec.executables   = Dir["exe/*"].map { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  ## Runtime dependencies:
  spec.add_dependency "rbnacl",  ">= 7.0"
  spec.add_dependency "ffi",     ">= 1.15"
  spec.add_dependency "sqlite3", ">= 1.6"

  ## Development dependencies:
  spec.add_development_dependency "rake",     ">= 13.0"
  spec.add_development_dependency "minitest", ">= 5.0"
end
