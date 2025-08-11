# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::BaseValidator do
  let(:config) { double("Configuration") }
  let(:logger) { double("Logger", error: nil) }
  let(:validator) { described_class.new(config, logger: logger) }

  describe "#initialize" do
    it "initializes with config" do
      expect(validator.config).to eq(config)
    end

    it "initializes with logger" do
      expect(validator.logger).to eq(logger)
    end

    it "initializes with nil logger when not provided" do
      validator = described_class.new(config)
      expect(validator.logger).to be_nil
    end
  end

  describe "private methods" do
    describe "#log_error" do
      it "logs error message when logger is available" do
        expect(logger).to receive(:error).with("Test error")
        validator.send(:log_error, "Test error")
      end

      it "doesn't raise when logger is nil" do
        validator = described_class.new(config, logger: nil)
        expect { validator.send(:log_error, "Test error") }.not_to raise_error
      end
    end

    describe "#sha256" do
      it "returns a SHA256 digest instance" do
        expect(validator.send(:sha256)).to be_an_instance_of(OpenSSL::Digest)
        expect(validator.send(:sha256).name).to eq("SHA256")
      end
    end

    describe "#decode_base64" do
      it "decodes base64 string" do
        encoded = Base64.strict_encode64("test_data")
        expect(validator.send(:decode_base64, encoded)).to eq("test_data")
      end
    end

    describe "#encode_base64" do
      it "encodes string to base64" do
        expect(validator.send(:encode_base64, "test_data")).to eq(Base64.strict_encode64("test_data"))
      end
    end
  end
end
