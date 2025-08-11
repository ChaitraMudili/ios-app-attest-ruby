# frozen_string_literal: true

module IosAppAttest
  # Configuration class for IosAppAttest
  #
  # This class holds all configuration parameters required for the iOS App Attest
  # verification process. It includes the app identifier and encryption key for challenge nonce encryption/decryption.
  #
  # @example
  #   IosAppAttest.configure do |config|
  #     config.app_id = "TEAM_ID.BUNDLE_ID"
  #     config.encryption_key = ENV["IOS_APP_ATTEST_TOKEN"].byteslice(0, 32)
  #   end
  #
  # @attr [String] app_id The Apple Team ID and Bundle ID in the format "TEAM_ID.BUNDLE_ID"
  # @attr [String] encryption_key The encryption key used for challenge nonce encryption (32 bytes)
  class Configuration
    attr_accessor :app_id, :encryption_key
    
    # Initialize a new Configuration instance with default values
    #
    # Creates a new configuration object with all attributes set to nil.
    # These attributes must be set before using the configuration with validators.
    #
    # @return [IosAppAttest::Configuration] A new Configuration instance with nil values
    def initialize
      @app_id = nil
      @encryption_key = nil
    end
  end
end
