# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Base class for all validators in the iOS App Attest validation process
    #
    # This class provides common functionality used by all validator classes,
    # including logging, cryptographic utilities, and base64 encoding/decoding.
    # All specific validators inherit from this class.
    #
    # @abstract Subclass and override validation methods to implement specific validation logic
    class BaseValidator
      attr_reader :config, :logger
      
      # Initialize the validator
      # @param config [IosAppAttest::Configuration] Configuration object
      # @param logger [Object] Logger instance (optional)
      def initialize(config, logger: nil)
        @config = config
        @logger = logger
      end
      
      private
      
      # Log error if logger is available
      # @param message [String] The error message to log
      def log_error(message)
        logger&.error(message)
      end
      
      # Get SHA256 digest
      # @return [OpenSSL::Digest] SHA256 digest instance
      def sha256
        @sha256 ||= OpenSSL::Digest.new('SHA256')
      end
      
      # Decode base64 string
      # @param base64_string [String] The base64 encoded string
      # @return [String] The decoded string
      def decode_base64(base64_string)
        Base64.decode64(base64_string)
      end
      
      # Encode base64 string
      # @param string [String] The string to encode
      # @return [String] The base64 encoded string
      def encode_base64(string)
        Base64.strict_encode64(string)
      end
    end
  end
end
