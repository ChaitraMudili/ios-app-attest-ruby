# frozen_string_literal: true

require 'pry'
require_relative 'validators'

module IosAppAttest
  # Verifies iOS App Attestation tokens
  # 
  # The Verifier class is responsible for validating iOS App Attestation tokens
  # received from iOS clients. It performs a series of validation steps to ensure
  # the attestation is genuine and comes from a valid Apple device.
  #
  # @example Basic usage
  #   verifier = IosAppAttest::Verifier.new(attestation_params)
  #   public_key, receipt = verifier.verify
  #
  # @example With Redis for nonce validation
  #   verifier = IosAppAttest::Verifier.new(
  #     attestation_params,
  #     redis_client: redis
  #   )
  #   public_key, receipt = verifier.verify
  class Verifier

    attr_reader :attestation_params, :redis_client, :logger

    # Initialize the verifier with attestation parameters
    # @param attestation_params [Hash] The attestation parameters from the client
    # @param redis_client [Object] Redis client for nonce verification (optional)
    # @param logger [Object] Logger instance (optional)
    def initialize(attestation_params, redis_client: nil, logger: nil)
      @attestation_params = attestation_params
      @redis_client = redis_client
      @logger = logger
      initialize_validators
    end

    # Verify the app attestation
    # 
    # This method performs a complete verification of the iOS App Attestation token.
    # It validates the attestation structure, certificate chain, challenge nonce,
    # and app identity. If all validations pass, it returns the public key and receipt.
    #
    # @return [Array<String>] An array containing [public_key, receipt] if verification succeeds
    # @raise [VerificationError] If verification fails for any reason
    # @raise [NonceError] If nonce validation fails
    # @raise [CertificateError] If certificate validation fails
    # @raise [ChallengeError] If challenge validation fails
    # @raise [AppIdentityError] If app identity validation fails
    # @raise [AttestationError] If attestation format is invalid
    def verify
      begin
        # Step 1: Decode the attestation object
        attestation = decode_attestation
        
        # Step 2: Validate the challenge nonce if Redis client is provided
        if redis_client
          challenge_validator.validate_nonce(challenge_id, challenge_decrypted)
        end
        
        # Step 3: Validate the attestation structure and format
        attestation_validator.validate(attestation)
        
        # Step 4: Extract auth_data and receipt
        auth_data = attestation_validator.extract_auth_data(attestation)
        @receipt = attestation_validator.extract_receipt(attestation)
        
        # Step 5: Validate the certificate chain and get the credential certificate
        cred_cert = certificate_validator.validate(attestation)
        
        # Step 6: Validate the challenge
        challenge_validator.validate_challenge(cred_cert, challenge_decrypted, auth_data)
        
        # Step 7: Validate the key ID
        challenge_validator.validate_key_id(cred_cert, key_id)
        
        # Step 8: Validate the certificate sequence structure
        certificate_validator.validate_sequence(cred_cert)
        
        # Step 9: Verify the app identity
        app_identity_validator.validate(auth_data, key_id)
        
        # Step 10: Extract the public key
        @public_key = certificate_validator.extract_public_key(cred_cert)
      rescue IosAppAttest::Error => error
        # Re-raise IosAppAttest errors directly
        log_error("IosAppAttest verification failed: #{error}")
        raise error
      rescue StandardError => error
        # Wrap other errors in VerificationError
        log_error("IosAppAttest verification failed: #{error}")
        raise VerificationError, "Attestation verification failed: #{error.message}"
      end
      
      [public_key, receipt]
    end
    
    private
    
    attr_reader :attestation_validator, :certificate_validator, :challenge_validator, 
                :app_identity_validator, :public_key, :receipt
    
    # Initialize all validators
    def initialize_validators
      @attestation_validator = Validators::AttestationValidator.new(config, logger: logger)
      @certificate_validator = Validators::CertificateValidator.new(config, logger: logger)
      @challenge_validator = Validators::ChallengeValidator.new(
        config, 
        redis_client: redis_client, 
        logger: logger
      )
      @app_identity_validator = Validators::AppIdentityValidator.new(config, logger: logger)
    end
    
    # Get IosAppAttest configuration
    # @return [IosAppAttest::Configuration] The configuration object
    def config
      IosAppAttest.configuration
    end
    
    # Decrypt challenge using AES
    # @return [String] The decrypted challenge
    def challenge_decrypted
      challenge_validator.decrypt_challenge(challenge, iv)
    end
    
    #---------------------------
    # Parameter Accessors
    #---------------------------

    # Get key ID from attestation parameters
    # @return [String] The key ID
    def key_id
      @key_id ||= attestation_params[:key_id] || attestation_params["key_id"]
    end
    
    # Get attestation object from attestation parameters
    # @return [String] The decoded attestation object
    def attestation_object
      @attestation_object ||= Validators::Utils.decode_base64(attestation_params[:attestation_object] || attestation_params["attestation_object"])
    end

    # Get challenge ID from attestation parameters
    # @return [String] The challenge nonce ID
    def challenge_id
      @challenge_id ||= attestation_params[:challenge_nonce_id] || attestation_params["challenge_nonce_id"]
    end
    
    # Get challenge from attestation parameters
    # @return [String] The decoded challenge nonce
    def challenge
      @challenge ||= Validators::Utils.decode_base64(attestation_params[:challenge_nonce] || attestation_params["challenge_nonce"])
    end

    # Get IV from attestation parameters
    # @return [String] The decoded initialization vector
    def iv
      @iv ||= Validators::Utils.decode_base64(attestation_params[:initialization_vector] || attestation_params["initialization_vector"])
    end
    
    # Log error if logger is available
    # @param message [String] The error message to log
    def log_error(message)
      logger&.error(message)
    end
    
    # Decode the attestation object from base64
    # @return [Hash] The decoded attestation object
    def decode_attestation
      CBOR.decode(attestation_object)
    end
  end
end
