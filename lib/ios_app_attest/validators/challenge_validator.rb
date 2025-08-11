# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Validates challenge nonce and related aspects of the attestation
    #
    # This validator is responsible for verifying the challenge nonce used in the
    # attestation process. It validates that the nonce is valid, not expired, and
    # matches the expected value. It also verifies the key ID against the certificate's
    # public key and provides methods for decrypting challenges.
    #
    # @example
    #   validator = IosAppAttest::Validators::ChallengeValidator.new(config, redis_client: redis)
    #   validator.validate_nonce(challenge_id, challenge_decrypted)
    #   validator.validate_challenge(cred_cert, challenge_decrypted, auth_data)
    #   validator.validate_key_id(cred_cert, key_id)
    class ChallengeValidator < BaseValidator
      attr_reader :redis_client
      
      # Initialize the challenge validator
      #
      # This initializes the validator with configuration and optional Redis client.
      # The Redis client is used to store and retrieve nonces for verification.
      # If no Redis client is provided, nonce verification will be skipped.
      #
      # @param config [IosAppAttest::Configuration] Configuration object with encryption keys and OIDs
      # @param redis_client [Object] Redis client for nonce verification (optional)
      # @param logger [Object] Logger instance for logging validation events (optional)
      def initialize(config, redis_client: nil, logger: nil)
        super(config, logger: logger)
        @redis_client = redis_client
      end
      
      # Validate the challenge nonce against stored value
      #
      # This method verifies that the provided challenge nonce matches the one
      # previously stored in Redis. After successful validation, the nonce is
      # deleted from Redis to prevent replay attacks.
      #
      # @note This method requires a Redis client to be provided during initialization.
      #       If no Redis client is available, this validation is skipped.
      #
      # @param challenge_id [String] The challenge nonce ID used as Redis key
      # @param challenge_decrypted [String] The decrypted challenge nonce to validate
      # @raise [IosAppAttest::ChallengeError] If nonce is invalid, expired, or missing
      def validate_nonce(challenge_id, challenge_decrypted)
        return unless redis_client
        
        nonce = redis_client.get("nonce:#{challenge_id}")
        unless nonce && nonce == encode_base64(challenge_decrypted)
          raise IosAppAttest::ChallengeError, "Invalid or expired challenge nonce"
        end
        
        # Delete the nonce after successful validation to prevent replay attacks
        redis_client.del("nonce:#{challenge_id}")
      end
      
      # Verify challenge nonce from certificate
      #
      # This method verifies that the challenge nonce was correctly incorporated into
      # the attestation by checking that the certificate contains a hash derived from
      # the authentication data and challenge nonce. This ensures the attestation was
      # created specifically for this challenge.
      #
      # @param cred_cert [OpenSSL::X509::Certificate] The credential certificate containing the App Attest extension
      # @param challenge_decrypted [String] The decrypted challenge nonce to verify
      # @param auth_data [String] The authentication data from the attestation
      # @raise [IosAppAttest::ChallengeError] If challenge verification fails
      def validate_challenge(cred_cert, challenge_decrypted, auth_data)
        challenge_hash = sha256.digest(challenge_decrypted)

        extension = cred_cert.extensions.find { |e| e.oid == app_attest_oid }
        sequence = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value[1].value)
        to_verify = sequence.value[0].value[0].value

        expected_hash = sha256.digest(auth_data + challenge_hash)
        unless to_verify == expected_hash
          raise IosAppAttest::ChallengeError, 'Challenge verification failed'
        end
      end
      
      # Validate the key ID matches the certificate's public key
      #
      # This method verifies that the key ID provided in the attestation parameters
      # matches the hash of the public key from the credential certificate. This ensures
      # the attestation is using the correct key pair.
      #
      # @param cred_cert [OpenSSL::X509::Certificate] The credential certificate containing the public key
      # @param key_id [String] The key ID from attestation parameters to verify
      # @raise [IosAppAttest::ChallengeError] If key ID verification fails
      def validate_key_id(cred_cert, key_id)
        uncompressed_point_key = cred_cert.public_key.public_key.to_octet_string(:uncompressed)
        expected_key_id = Base64.strict_encode64(sha256.digest(uncompressed_point_key))
        
        unless key_id == expected_key_id
          raise IosAppAttest::ChallengeError, 'Key ID verification failed'
        end
      end
      
      # Decrypt challenge using AES-256-CBC
      #
      # This method decrypts the challenge nonce using AES-256-CBC encryption with
      # the provided initialization vector and the encryption key from configuration.
      #
      # @param challenge [String] The encrypted challenge nonce
      # @param iv [String] The initialization vector used for encryption
      # @return [String] The decrypted challenge nonce
      def decrypt_challenge(challenge, iv)
        cipher = OpenSSL::Cipher::AES256.new(:CBC)
        cipher.decrypt
        cipher.key = encryption_key
        cipher.iv = iv
        cipher.update(challenge) + cipher.final
      end
      
      private
      
      # Apple App Attest OID constant
      # This OID identifies the App Attest extension in certificates
      APP_ATTEST_OID = "1.2.840.113635.100.8.2"
      
      # Get app attest OID
      #
      # This method returns the hardcoded Apple App Attest OID.
      # The OID is used to identify the App Attest extension in certificates.
      #
      # @return [String] The Apple App Attest OID ("1.2.840.113635.100.8.2")
      def app_attest_oid
        APP_ATTEST_OID
      end
      
      # Get encryption key from configuration
      #
      # This method retrieves the encryption key from the configuration object.
      # The key is used for decrypting challenge nonces.
      #
      # @return [String] The encryption key used for AES-256-CBC decryption
      def encryption_key
        config.encryption_key
      end
    end
  end
end
