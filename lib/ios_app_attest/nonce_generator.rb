# frozen_string_literal: true

require "openssl"
require "base64"
require "securerandom"

module IosAppAttest
  # Generates and manages challenge nonces for iOS App Attestation
  #
  # The NonceGenerator class is responsible for creating secure random nonces,
  # encrypting them, and storing them in Redis for later validation during
  # the attestation verification process.
  #
  # This class uses IosAppAttest::NonceError for error handling.
  #
  # @example Basic usage
  #   redis = Redis.new
  #   generator = IosAppAttest::NonceGenerator.new(redis_client: redis)
  #   nonce_data = generator.generate
  #
  # @example With custom expiry time
  #   generator = IosAppAttest::NonceGenerator.new(
  #     redis_client: redis,
  #     expiry_seconds: 300
  #   )
  #   nonce_data = generator.generate
  class NonceGenerator

    attr_reader :redis_client, :logger, :expiry_seconds

    # Initialize the nonce generator
    # @param redis_client [Object] Redis client for nonce storage
    # @param logger [Object] Logger instance (optional)
    # @param expiry_seconds [Integer] Nonce expiry time in seconds (default: 120)
    def initialize(redis_client:, logger: nil, expiry_seconds: 120)
      @redis_client = redis_client
      @logger = logger
      @expiry_seconds = expiry_seconds
    end

    # Generate a new nonce and store it in Redis
    #
    # This method generates a cryptographically secure random nonce,
    # encrypts it using AES-256-CBC, and stores it in Redis for later validation.
    # The nonce is stored with an expiry time specified during initialization.
    #
    # @return [Hash] Hash containing:
    #   - :challenge_nonce_id [String] A unique identifier for the challenge
    #   - :challenge_nonce [String] Base64-encoded encrypted challenge nonce
    #   - :initialization_vector [String] Base64-encoded initialization vector
    # @raise [IosAppAttest::NonceError] If nonce generation fails due to Redis errors or configuration issues
    def generate
      begin
        store_nonce_in_redis
        encrypted_nonce, iv = encrypt
      rescue IosAppAttest::Error => error
        # Re-raise IosAppAttest errors directly
        log_error("IosAppAttest nonce generation failed: #{error}")
        raise error
      rescue StandardError => error
        # Wrap other errors in NonceGenerationError
        log_error("IosAppAttest nonce generation failed: #{error}")
        raise IosAppAttest::NonceError, "Nonce generation failed: #{error.message}"
      end

      {
        challenge_nonce_id: nonce_id,
        challenge_nonce: base64_encode(encrypted_nonce),
        initialization_vector: base64_encode(iv)
      }
    end

    private

    # Encrypt the raw nonce using AES-256-CBC
    def encrypt
      cipher.encrypt
      iv = cipher.random_iv
      cipher.key = encryption_key
      cipher.iv = iv
      encrypted = cipher.update(raw_nonce) + cipher.final
      [encrypted, iv]
    end

    # Get AES cipher
    def cipher
      @cipher ||= OpenSSL::Cipher::AES256.new(:CBC)
    end

    # Generate a random nonce
    def raw_nonce
      @raw_nonce ||= SecureRandom.random_bytes(32)
    end

    # Generate a unique nonce ID
    def nonce_id
      @nonce_id ||= SecureRandom.uuid
    end

    # Store the nonce in Redis with expiry
    def store_nonce_in_redis
      redis_client.set("nonce:#{nonce_id}", base64_encode(raw_nonce), ex: expiry_seconds)
    end

    # Get encryption key from configuration
    def encryption_key
      key = IosAppAttest.configuration.encryption_key
      raise IosAppAttest::NonceError, "Encryption key not configured" unless key
      key
    end

    # Encode base64 string
    def base64_encode(base64_string)
      Base64.strict_encode64(base64_string)
    end

    # Log error if logger is available
    def log_error(message)
      logger&.error(message)
    end
  end
end
