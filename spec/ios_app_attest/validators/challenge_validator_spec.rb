# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::ChallengeValidator do
  let(:config) { double("Configuration", encryption_key: "0" * 32) }
  let(:redis_client) { double("Redis") }
  let(:logger) { double("Logger", error: nil) }
  let(:validator) { described_class.new(config, redis_client: redis_client, logger: logger) }
  
  let(:challenge_id) { "test-challenge-id" }
  let(:challenge_decrypted) { "decrypted_challenge_data" }
  let(:base64_challenge) { Base64.strict_encode64(challenge_decrypted) }
  let(:auth_data) { "auth_data" }
  let(:challenge_hash) { OpenSSL::Digest.new('SHA256').digest(challenge_decrypted) }
  let(:expected_hash) { OpenSSL::Digest.new('SHA256').digest(auth_data + challenge_hash) }
  
  let(:mock_cred_cert) { instance_double(OpenSSL::X509::Certificate) }
  let(:mock_extension) { instance_double(OpenSSL::X509::Extension, oid: "1.2.840.113635.100.8.2", to_der: "extension_der_data") }
  let(:mock_public_key) { double('PublicKey', public_key: mock_ec_key) }
  let(:mock_ec_key) { double('ECPoint') }
  
  let(:mock_asn1_sequence) do
    mock_value00 = double('ASN1Value00', value: expected_hash)
    mock_value0 = double('ASN1Value0', value: [mock_value00])
    
    double('ASN1Sequence', value: [mock_value0])
  end
  
  let(:mock_asn1_value) do
    double('ASN1Value', value: [nil, mock_asn1_value2])
  end
  
  let(:mock_asn1_value2) do
    double('ASN1Value2', value: "inner_value")
  end

  before do
    # Mock certificate extensions
    allow(mock_cred_cert).to receive(:extensions).and_return([mock_extension])
    
    # Mock ASN1 decoding
    allow(OpenSSL::ASN1).to receive(:decode).with("extension_der_data").and_return(mock_asn1_value)
    allow(OpenSSL::ASN1).to receive(:decode).with("inner_value").and_return(mock_asn1_sequence)
    
    # Mock public key for key_id validation
    allow(mock_cred_cert).to receive(:public_key).and_return(mock_public_key)
    allow(mock_public_key).to receive(:public_key).and_return(mock_ec_key)
    allow(mock_ec_key).to receive(:to_octet_string).with(:uncompressed).and_return("uncompressed_key")
  end

  describe "#initialize" do
    it "initializes with redis client" do
      expect(validator.redis_client).to eq(redis_client)
    end

    it "initializes with nil redis client when not provided" do
      validator = described_class.new(config)
      expect(validator.redis_client).to be_nil
    end
  end

  describe "#validate_nonce" do
    context "when redis client is provided" do
      before do
        allow(redis_client).to receive(:get).with("nonce:#{challenge_id}").and_return(base64_challenge)
        allow(redis_client).to receive(:del)
      end

      it "passes when nonce is valid" do
        expect { validator.validate_nonce(challenge_id, challenge_decrypted) }.not_to raise_error
      end

      it "deletes the nonce after successful validation" do
        expect(redis_client).to receive(:del).with("nonce:#{challenge_id}")
        validator.validate_nonce(challenge_id, challenge_decrypted)
      end

      context "when nonce is invalid" do
        before do
          allow(redis_client).to receive(:get).with("nonce:#{challenge_id}").and_return("invalid_nonce")
        end

        it "raises VerificationError" do
          expect { validator.validate_nonce(challenge_id, challenge_decrypted) }.to raise_error(
            IosAppAttest::ChallengeError,
            /Invalid or expired challenge nonce/
          )
        end
      end

      context "when nonce is missing" do
        before do
          allow(redis_client).to receive(:get).with("nonce:#{challenge_id}").and_return(nil)
        end

        it "raises VerificationError" do
          expect { validator.validate_nonce(challenge_id, challenge_decrypted) }.to raise_error(
            IosAppAttest::ChallengeError,
            /Invalid or expired challenge nonce/
          )
        end
      end
    end

    context "when redis client is not provided" do
      let(:validator) { described_class.new(config, redis_client: nil) }

      it "does not perform validation" do
        # The implementation checks redis_client directly, not through a method call
        # Just verify that no error is raised
        expect { validator.validate_nonce(challenge_id, challenge_decrypted) }.not_to raise_error
      end
    end
  end

  describe "#validate_challenge" do
    it "passes when challenge verification succeeds" do
      expect { validator.validate_challenge(mock_cred_cert, challenge_decrypted, auth_data) }.not_to raise_error
    end

    context "when challenge verification fails" do
      let(:different_challenge) { "different_challenge" }
      let(:different_hash) { OpenSSL::Digest.new('SHA256').digest(different_challenge) }

      before do
        # Mock with different challenge hash
        allow(OpenSSL::Digest).to receive_message_chain(:new, :digest).and_return(different_hash)
      end

      it "raises VerificationError" do
        expect { validator.validate_challenge(mock_cred_cert, different_challenge, auth_data) }.to raise_error(
          IosAppAttest::ChallengeError,
          /Challenge verification failed/
        )
      end
    end
  end

  describe "#validate_key_id" do
    let(:key_id) { Base64.strict_encode64(OpenSSL::Digest.new('SHA256').digest("uncompressed_key")) }

    it "passes when key ID matches" do
      expect { validator.validate_key_id(mock_cred_cert, key_id) }.not_to raise_error
    end

    context "when key ID doesn't match" do
      let(:invalid_key_id) { "invalid_key_id" }

      it "raises VerificationError" do
        expect { validator.validate_key_id(mock_cred_cert, invalid_key_id) }.to raise_error(
          IosAppAttest::ChallengeError,
          /Key ID verification failed/
        )
      end
    end
  end

  describe "#decrypt_challenge" do
    let(:encrypted_challenge) { "encrypted_challenge_data" }
    let(:iv) { "initialization_vector" }

    before do
      cipher_double = instance_double(OpenSSL::Cipher::AES256)
      allow(OpenSSL::Cipher::AES256).to receive(:new).and_return(cipher_double)
      allow(cipher_double).to receive(:decrypt)
      allow(cipher_double).to receive(:key=)
      allow(cipher_double).to receive(:iv=)
      allow(cipher_double).to receive(:update).and_return("decrypted_part1")
      allow(cipher_double).to receive(:final).and_return("_part2")
    end

    it "decrypts the challenge using AES" do
      expect(validator.decrypt_challenge(encrypted_challenge, iv)).to eq("decrypted_part1_part2")
    end
  end

  describe "private methods" do
    describe "#app_attest_oid" do
      it "returns hardcoded App Attest OID constant" do
        expect(validator.send(:app_attest_oid)).to eq(described_class::APP_ATTEST_OID)
      end
    end

    describe "#encryption_key" do
      it "returns encryption key from configuration" do
        expect(validator.send(:encryption_key)).to eq("0" * 32)
      end
    end
  end
end
