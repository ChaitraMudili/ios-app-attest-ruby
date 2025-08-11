# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::NonceGenerator do
  let(:redis_client) { double("Redis") }
  let(:logger) { double("Logger", error: nil) }
  let(:expiry_seconds) { 300 }
  let(:nonce_generator) { described_class.new(redis_client: redis_client, logger: logger, expiry_seconds: expiry_seconds) }
  
  let(:nonce_id) { "test-uuid" }
  let(:raw_nonce) { "raw_nonce_data" }
  let(:encrypted_nonce) { "encrypted_nonce_data" }
  let(:iv) { "initialization_vector" }
  let(:base64_encrypted_nonce) { Base64.strict_encode64(encrypted_nonce) }
  let(:base64_iv) { Base64.strict_encode64(iv) }

  before do
    IosAppAttest.configure do |config|
      config.encryption_key = "0" * 32
    end
    
    allow(SecureRandom).to receive(:uuid).and_return(nonce_id)
    allow(SecureRandom).to receive(:random_bytes).and_return(raw_nonce)
    allow(redis_client).to receive(:set)
  end

  describe "#initialize" do
    it "initializes with redis client" do
      expect(nonce_generator.redis_client).to eq(redis_client)
    end

    it "initializes with logger" do
      expect(nonce_generator.logger).to eq(logger)
    end

    it "initializes with expiry seconds" do
      expect(nonce_generator.expiry_seconds).to eq(expiry_seconds)
    end

    it "uses default expiry seconds when not provided" do
      generator = described_class.new(redis_client: redis_client)
      expect(generator.expiry_seconds).to eq(120)
    end
  end

  describe "#generate" do
    before do
      cipher_double = instance_double(OpenSSL::Cipher::AES256)
      allow(OpenSSL::Cipher::AES256).to receive(:new).and_return(cipher_double)
      allow(cipher_double).to receive(:encrypt)
      allow(cipher_double).to receive(:random_iv).and_return(iv)
      allow(cipher_double).to receive(:key=)
      allow(cipher_double).to receive(:iv=)
      allow(cipher_double).to receive(:update).and_return(encrypted_nonce)
      allow(cipher_double).to receive(:final).and_return("")
    end

    it "returns a hash with challenge nonce details" do
      result = nonce_generator.generate
      expect(result).to include(
        challenge_nonce_id: nonce_id,
        challenge_nonce: base64_encrypted_nonce,
        initialization_vector: base64_iv
      )
    end

    it "stores the nonce in redis" do
      expect(redis_client).to receive(:set).with(
        "nonce:#{nonce_id}",
        Base64.strict_encode64(raw_nonce),
        ex: expiry_seconds
      )
      nonce_generator.generate
    end

    context "when encryption fails" do
      before do
        allow(nonce_generator).to receive(:encrypt).and_raise(StandardError.new("Encryption failed"))
      end

      it "logs the error" do
        expect(logger).to receive(:error).with(/IosAppAttest nonce generation failed/)
        expect { nonce_generator.generate }.to raise_error(IosAppAttest::NonceError)
      end

      it "raises NonceGenerationError" do
        expect { nonce_generator.generate }.to raise_error(
          IosAppAttest::NonceError,
          /Nonce generation failed: Encryption failed/
        )
      end
    end

    context "when encryption key is not configured" do
      before do
        IosAppAttest.configure do |config|
          config.encryption_key = nil
        end
      end

      it "raises NonceGenerationError" do
        expect { nonce_generator.generate }.to raise_error(
          IosAppAttest::NonceError,
          /Encryption key not configured/
        )
      end
    end
  end

  describe "private methods" do
    describe "#log_error" do
      it "logs error message when logger is available" do
        expect(logger).to receive(:error).with("Test error")
        nonce_generator.send(:log_error, "Test error")
      end

      it "doesn't raise when logger is nil" do
        generator = described_class.new(redis_client: redis_client, logger: nil)
        expect { generator.send(:log_error, "Test error") }.not_to raise_error
      end
    end

    describe "#base64_encode" do
      it "encodes data to base64" do
        data = "test_data"
        expect(nonce_generator.send(:base64_encode, data)).to eq(Base64.strict_encode64(data))
      end
    end

    describe "#nonce_id" do
      it "generates a UUID" do
        expect(nonce_generator.send(:nonce_id)).to eq(nonce_id)
      end
    end

    describe "#raw_nonce" do
      it "generates random bytes" do
        expect(nonce_generator.send(:raw_nonce)).to eq(raw_nonce)
      end
    end
  end
end
