# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Validates app identity using authentication data
    #
    # This validator is responsible for verifying the application identity
    # by checking the authentication data from the attestation object.
    # It validates the relying party ID hash, sign count, AAGUID, and credential ID.
    #
    # @example
    #   validator = IosAppAttest::Validators::AppIdentityValidator.new(config)
    #   validator.validate(auth_data, key_id)
    class AppIdentityValidator < BaseValidator
      # Verify app identity using authentication data
      #
      # This method performs the following validations:
      # 1. Unpacks the authentication data to extract required components
      # 2. Verifies the relying party ID hash matches the configured app ID
      # 3. Ensures the sign count is zero (required for initial attestation)
      # 4. Validates the AAGUID matches the expected Apple App Attest value
      # 5. Verifies the credential ID matches the provided key ID
      #
      # @param auth_data [String] The authentication data from the attestation object
      # @param key_id [String] The key ID from attestation parameters
      # @raise [IosAppAttest::AppIdentityError] If any app identity verification check fails
      def validate(auth_data, key_id)
        rp_id_hash, sign_count, aaguid, credential_id = unpack_auth_data(auth_data)
        
        # Verify relying party ID hash
        unless rp_id_hash == sha256.digest(app_id)
          raise IosAppAttest::AppIdentityError, 'App ID verification failed'
        end
        
        # Verify sign count is zero (first attestation)
        unless sign_count.zero?
          raise IosAppAttest::AppIdentityError, 'Sign counter must be zero for initial attestation'
        end
        
        # Verify AAGUID
        unless validate_aaguid(aaguid)
          raise IosAppAttest::AppIdentityError, 'Invalid AAGUID for App Attestation'
        end
        
        # Verify credential ID matches key ID
        unless key_id == Base64.strict_encode64(credential_id)
          raise IosAppAttest::AppIdentityError, 'Credential ID does not match key ID'
        end
      end
      
      private
      
      # Unpack required objects from authentication data
      #
      # This method parses the binary authentication data according to the
      # WebAuthn/FIDO2 specification format to extract the components needed
      # for app identity validation.
      #
      # @param auth_data [String] The authentication data from the attestation object
      # @return [Array] Array containing [rp_id_hash, sign_count, aaguid, credential_id]
      def unpack_auth_data(auth_data)
        (rp_id_hash, flags, sign_count, trailing_bytes) =
          auth_data.unpack('a32c1N1a*')
      
        (aaguid, credential_id_length, trailing_bytes) =
          trailing_bytes.unpack('a16na*')
      
        (credential_id, credential_public_key) =
          trailing_bytes.unpack("a#{credential_id_length}a*")
      
        [rp_id_hash, sign_count, aaguid, credential_id]
      end
      
      # Validate AAGUID (Authenticator Attestation Globally Unique Identifier)
      #
      # This method checks if the AAGUID matches the expected value for
      # Apple App Attestation. In non-production environments, it also
      # accepts the development AAGUID value.
      #
      # @param aaguid [String] The AAGUID extracted from authentication data
      # @return [Boolean] True if AAGUID is valid for App Attestation
      def validate_aaguid(aaguid)
        expected_aaguid = "appattest\x00\x00\x00\x00\x00\x00\x00"
        
        # Allow development AAGUID in non-production environments
        if ENV['IOS_APP_ATTEST_ENV'] != 'production'
          aaguid == 'appattestdevelop' || aaguid == expected_aaguid
        else
          aaguid == expected_aaguid
        end
      end
      
      # Get app ID from configuration
      #
      # This method retrieves the application identifier from the configuration.
      # The app ID is used to verify the relying party ID hash in the authentication data.
      #
      # @return [String] The configured application identifier
      def app_id
        config.app_id
      end
    end
  end
end
