# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Configuration do
  let(:configuration) { described_class.new }

  describe "#initialize" do
    it "initializes with nil values" do
      expect(configuration.app_id).to be_nil
      expect(configuration.encryption_key).to be_nil
    end
  end

  describe "attributes" do
    it "allows setting app_id" do
      configuration.app_id = "com.example.app"
      expect(configuration.app_id).to eq("com.example.app")
    end



    # app_attest_oid is now a hardcoded constant in the validator classes

    it "allows setting encryption_key" do
      configuration.encryption_key = "encryption_key_data"
      expect(configuration.encryption_key).to eq("encryption_key_data")
    end
  end
end

RSpec.describe IosAppAttest do
  describe ".configure" do
    before do
      # Reset configuration before each test
      IosAppAttest.instance_variable_set(:@configuration, nil)
    end

    it "creates a new configuration if none exists" do
      expect(IosAppAttest.configuration).to be_nil
      IosAppAttest.configure
      expect(IosAppAttest.configuration).to be_an_instance_of(IosAppAttest::Configuration)
    end

    it "yields the configuration if block is given" do
      yielded_config = nil
      IosAppAttest.configure do |config|
        yielded_config = config
        config.app_id = "com.example.app"
      end
      expect(yielded_config).to be_an_instance_of(IosAppAttest::Configuration)
      expect(IosAppAttest.configuration.app_id).to eq("com.example.app")
    end

    it "does not override existing configuration" do
      IosAppAttest.configure do |config|
        config.app_id = "com.example.app"
      end
      
      IosAppAttest.configure do |config|
        config.encryption_key = "encryption_key_data"
      end
      
      expect(IosAppAttest.configuration.app_id).to eq("com.example.app")
      expect(IosAppAttest.configuration.encryption_key).to eq("encryption_key_data")
    end
  end

  describe ".configuration" do
    before do
      IosAppAttest.instance_variable_set(:@configuration, nil)
      IosAppAttest.configure
    end

    it "returns the configuration" do
      expect(IosAppAttest.configuration).to be_an_instance_of(IosAppAttest::Configuration)
    end
  end
end
