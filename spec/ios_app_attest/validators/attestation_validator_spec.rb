# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::AttestationValidator do
  let(:config) { double("Configuration") }
  let(:logger) { double("Logger", error: nil) }
  let(:validator) { described_class.new(config, logger: logger) }

  let(:valid_attestation) do
    {
      'fmt' => 'apple-appattest',
      'attStmt' => { 'receipt' => 'receipt_data' },
      'authData' => 'auth_data'
    }
  end

  describe "#validate" do
    it "passes with valid attestation" do
      expect { validator.validate(valid_attestation) }.not_to raise_error
    end

    context "when missing required keys" do
      it "raises error when fmt is missing" do
        attestation = valid_attestation.dup
        attestation.delete('fmt')
        
        expect { validator.validate(attestation) }.to raise_error(
          IosAppAttest::AttestationError,
          /Missing required attestation keys: fmt/
        )
      end

      it "raises error when attStmt is missing" do
        attestation = valid_attestation.dup
        attestation.delete('attStmt')
        
        expect { validator.validate(attestation) }.to raise_error(
          IosAppAttest::AttestationError,
          /Missing required attestation keys: attStmt/
        )
      end

      it "raises error when authData is missing" do
        attestation = valid_attestation.dup
        attestation.delete('authData')
        
        expect { validator.validate(attestation) }.to raise_error(
          IosAppAttest::AttestationError,
          /Missing required attestation keys: authData/
        )
      end

      it "raises error when multiple keys are missing" do
        attestation = { 'fmt' => 'apple-appattest' }
        
        expect { validator.validate(attestation) }.to raise_error(
          IosAppAttest::AttestationError,
          /Missing required attestation keys: attStmt, authData/
        )
      end
    end

    context "when format is invalid" do
      it "raises error when format is not apple-appattest" do
        attestation = valid_attestation.dup
        attestation['fmt'] = 'invalid-format'
        
        expect { validator.validate(attestation) }.to raise_error(
          IosAppAttest::AttestationError,
          /Invalid attestation format: expected 'apple-appattest'/
        )
      end
    end
  end

  describe "#extract_receipt" do
    it "extracts receipt from attestation statement" do
      expect(validator.extract_receipt(valid_attestation)).to eq('receipt_data')
    end
  end

  describe "#extract_auth_data" do
    it "extracts auth data from attestation" do
      expect(validator.extract_auth_data(valid_attestation)).to eq('auth_data')
    end
  end
end
