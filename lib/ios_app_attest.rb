# frozen_string_literal: true

require "cbor"
require "openssl"
require "base64"
require "securerandom"
require_relative "ios_app_attest/version"
require_relative "ios_app_attest/configuration"
require_relative "ios_app_attest/errors"
require_relative "ios_app_attest/validators"
require_relative "ios_app_attest/verifier"
require_relative "ios_app_attest/nonce_generator"

# Main module for iOS App Attest verification
#
# This module provides functionality for verifying iOS App Attest attestations.
# It includes classes for configuration, verification, nonce generation, and
# various validators for different aspects of the attestation process.
#
# @example Basic usage
#   IosAppAttest.configure do |config|
#     config.app_id = "TEAM123.com.example.app"
#     config.encryption_key = SecureRandom.random_bytes(32)
#   end
#   # Note: App Attest OID ("1.2.840.113635.100.8.2") is hardcoded in the gem
#
#   verifier = IosAppAttest::Verifier.new
#   verifier.verify(attestation_object, challenge_id, key_id)
#
module IosAppAttest
  # Configuration options for the IosAppAttest module
  class << self
    attr_accessor :configuration
    
    # Configure the IosAppAttest module
    #
    # This method allows configuration of the IosAppAttest module using a block.
    # It yields the configuration object to the block, allowing for setting
    # various configuration parameters.
    #
    # @example
    #   IosAppAttest.configure do |config|
    #     config.app_id = "TEAM123.com.example.app"
    #     config.encryption_key = SecureRandom.random_bytes(32)
    #   end
    #   # Note: App Attest OID is hardcoded in the gem
    #
    # @yield [configuration] The configuration object to be modified
    # @return [Configuration] The current configuration object
    def configure
      self.configuration ||= Configuration.new
      yield(configuration) if block_given?
      configuration
    end
  end
  
  # Initialize with default configuration
  configure
end
