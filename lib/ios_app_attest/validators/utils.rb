# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Utility methods for iOS App Attest validators
    #
    # This module provides common cryptographic and encoding utilities
    # used throughout the iOS App Attest validation process.
    # It includes methods for base64 encoding/decoding, SHA256 hashing,
    # and AES cipher creation.
    module Utils
      # Decode base64 string
      # @param base64_string [String] The base64 encoded string
      # @return [String] The decoded string
      def self.decode_base64(base64_string)
        Base64.strict_decode64(base64_string)
      end
      
      # Encode base64 string
      # @param string [String] The string to encode
      # @return [String] The base64 encoded string
      def self.encode_base64(string)
        Base64.strict_encode64(string)
      end
      
      # Get SHA256 digest
      # @return [OpenSSL::Digest] SHA256 digest instance
      def self.sha256
        OpenSSL::Digest.new('SHA256')
      end
      
      # Create AES cipher
      # @return [OpenSSL::Cipher] AES256-CBC cipher instance
      def self.cipher
        OpenSSL::Cipher::AES256.new(:CBC)
      end
    end
  end
end
