# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Validates attestation structure and format
    #
    # This validator is responsible for verifying the structure and format
    # of the attestation object received from the Apple App Attest service.
    # It ensures the attestation contains all required keys and has the correct format.
    #
    # @example
    #   validator = IosAppAttest::Validators::AttestationValidator.new(config)
    #   validator.validate(attestation)
    class AttestationValidator < BaseValidator
      # Validate the attestation object structure
      # @param attestation [Hash] The decoded attestation object
      # @raise [IosAppAttest::AttestationError] If attestation structure is invalid
      def validate(attestation)
        required_keys = %w[fmt attStmt authData]
        missing_keys = required_keys - attestation.keys.map(&:to_s)

        if missing_keys.any?
          raise IosAppAttest::AttestationError, 
                "Missing required attestation keys: #{missing_keys.join(', ')}"
        end
        
        unless attestation['fmt'] == 'apple-appattest'
          raise IosAppAttest::AttestationError, 
                "Invalid attestation format: expected 'apple-appattest'"
        end
      end
      
      # Extract receipt from attestation statement
      #
      # This method extracts the App Store receipt from the attestation statement.
      # The receipt is used for additional verification with Apple's servers.
      #
      # @param attestation [Hash] The decoded attestation object
      # @return [String] The App Store receipt data
      def extract_receipt(attestation)
        attestation['attStmt']['receipt']
      end
      
      # Extract authentication data from attestation
      #
      # This method extracts the authentication data from the attestation object.
      # The authentication data contains important information like the relying party ID hash,
      # sign count, AAGUID, and credential ID needed for verification.
      #
      # @param attestation [Hash] The decoded attestation object
      # @return [String] The authentication data used for identity verification
      def extract_auth_data(attestation)
        attestation['authData']
      end
    end
  end
end
