# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Verifier do
  let(:attestation_params) do
    {
      key_id: "key_id_123",
      attestation_object: Base64.strict_encode64("attestation_object_data"),
      challenge_nonce_id: "challenge_id_123",
      challenge_nonce: Base64.strict_encode64("challenge_nonce_data"),
      initialization_vector: Base64.strict_encode64("iv_data")
    }
  end
  
  let(:redis_client) { double("Redis") }
  let(:logger) { double("Logger", error: nil) }
  let(:config) { double("Configuration", app_id: "com.example.app") }
  
  # Test data
  let(:decoded_attestation) { { "fmt" => "apple-appattest", "attStmt" => { "receipt" => "receipt_data" } } }
  let(:auth_data) { "auth_data" }
  let(:receipt) { "receipt_data" }
  let(:cred_cert) { double("Certificate") }
  let(:public_key) { "public_key_data" }
  let(:decrypted_challenge) { "decrypted_challenge" }
  
  # Mock validators
  let(:attestation_validator) { instance_double(IosAppAttest::Validators::AttestationValidator) }
  let(:certificate_validator) { instance_double(IosAppAttest::Validators::CertificateValidator) }
  let(:challenge_validator) { instance_double(IosAppAttest::Validators::ChallengeValidator) }
  let(:app_identity_validator) { instance_double(IosAppAttest::Validators::AppIdentityValidator) }
  
  # Subject
  let(:verifier) { described_class.new(attestation_params, redis_client: redis_client, logger: logger) }
  
  before do
    # Allow IosAppAttest.configuration to be called
    allow(IosAppAttest).to receive(:configuration).and_return(config)
    
    # Mock CBOR.decode
    allow(CBOR).to receive(:decode).and_return(decoded_attestation)
    
    # Set up validator expectations
    allow_any_instance_of(described_class).to receive(:initialize_validators) do |instance|
      instance.instance_variable_set(:@attestation_validator, attestation_validator)
      instance.instance_variable_set(:@certificate_validator, certificate_validator)
      instance.instance_variable_set(:@challenge_validator, challenge_validator)
      instance.instance_variable_set(:@app_identity_validator, app_identity_validator)
    end
    
    # Set up validator method expectations
    allow(attestation_validator).to receive(:validate)
    allow(attestation_validator).to receive(:extract_auth_data).and_return(auth_data)
    allow(attestation_validator).to receive(:extract_receipt).and_return(receipt)
    
    allow(certificate_validator).to receive(:validate).and_return(cred_cert)
    allow(certificate_validator).to receive(:validate_sequence)
    allow(certificate_validator).to receive(:extract_public_key).and_return(public_key)
    
    allow(challenge_validator).to receive(:validate_nonce)
    allow(challenge_validator).to receive(:validate_challenge)
    allow(challenge_validator).to receive(:validate_key_id)
    allow(challenge_validator).to receive(:decrypt_challenge).and_return(decrypted_challenge)
    
    allow(app_identity_validator).to receive(:validate)
  end

  describe "#initialize" do
    it "initializes with attestation parameters" do
      expect(verifier.attestation_params).to eq(attestation_params)
    end

    it "initializes with redis client" do
      expect(verifier.redis_client).to eq(redis_client)
    end

    it "initializes with logger" do
      expect(verifier.logger).to eq(logger)
    end
  end
  
  describe "#verify" do
    context "when verification succeeds" do
      it "returns public key and receipt" do
        # Set expectations
        expect(attestation_validator).to receive(:validate).with(decoded_attestation)
        expect(attestation_validator).to receive(:extract_auth_data).with(decoded_attestation).and_return(auth_data)
        expect(attestation_validator).to receive(:extract_receipt).with(decoded_attestation).and_return(receipt)
        expect(certificate_validator).to receive(:validate).with(decoded_attestation).and_return(cred_cert)
        expect(challenge_validator).to receive(:decrypt_challenge).and_return(decrypted_challenge)
        expect(challenge_validator).to receive(:validate_challenge).with(cred_cert, decrypted_challenge, auth_data)
        expect(challenge_validator).to receive(:validate_key_id).with(cred_cert, attestation_params[:key_id])
        expect(certificate_validator).to receive(:validate_sequence).with(cred_cert)
        expect(app_identity_validator).to receive(:validate).with(auth_data, attestation_params[:key_id])
        expect(certificate_validator).to receive(:extract_public_key).with(cred_cert).and_return(public_key)
        
        # When redis client is provided
        # Move this expectation before the verify call to ensure it's set up properly
        allow(challenge_validator).to receive(:validate_nonce).with(attestation_params[:challenge_nonce_id], decrypted_challenge)
        
        result = verifier.verify
        expect(result).to eq([public_key, receipt])
      end
    end

    context "when verification fails" do
      before do
        allow(attestation_validator).to receive(:validate).and_raise(StandardError.new("Attestation validation failed"))
      end
      
      it "logs the error" do
        expect(logger).to receive(:error).with(/IosAppAttest verification failed/)
        expect { verifier.verify }.to raise_error(IosAppAttest::VerificationError)
      end
      
      it "raises VerificationError" do
        expect { verifier.verify }.to raise_error(IosAppAttest::VerificationError, /Attestation verification failed/)
      end
    end
  end
end
