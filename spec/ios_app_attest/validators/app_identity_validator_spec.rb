# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::AppIdentityValidator do
  let(:config) { double("Configuration", app_id: "com.example.app") }
  let(:logger) { double("Logger", error: nil) }
  let(:validator) { described_class.new(config, logger: logger) }
  
  let(:app_id_hash) { OpenSSL::Digest.new('SHA256').digest("com.example.app") }
  let(:sign_count) { 0 }
  let(:aaguid) { "appattest\x00\x00\x00\x00\x00\x00\x00" }
  let(:credential_id) { "credential_id_data" }
  let(:key_id) { Base64.strict_encode64(credential_id) }
  
  # Create a valid auth_data binary string
  let(:auth_data) do
    flags = 0
    credential_id_length = credential_id.bytesize
    
    # Pack the auth_data according to the format in the validator
    [app_id_hash, flags, sign_count, aaguid, credential_id_length, credential_id, "public_key_data"].pack('a32c1N1a16na*a*')
  end

  describe "#validate" do
    it "passes with valid auth_data and key_id" do
      expect { validator.validate(auth_data, key_id) }.not_to raise_error
    end

    context "when app ID hash doesn't match" do
      let(:invalid_app_id_hash) { OpenSSL::Digest.new('SHA256').digest("invalid.app.id") }
      let(:auth_data_with_invalid_app_id) do
        flags = 0
        credential_id_length = credential_id.bytesize
        
        [invalid_app_id_hash, flags, sign_count, aaguid, credential_id_length, credential_id, "public_key_data"].pack('a32c1N1a16na*a*')
      end

      it "raises AppIdentityError" do
        expect { validator.validate(auth_data_with_invalid_app_id, key_id) }.to raise_error(
          IosAppAttest::AppIdentityError,
          /App ID verification failed/
        )
      end
    end

    context "when sign count is not zero" do
      let(:auth_data_with_nonzero_sign_count) do
        flags = 0
        non_zero_sign_count = 1
        credential_id_length = credential_id.bytesize
        
        [app_id_hash, flags, non_zero_sign_count, aaguid, credential_id_length, credential_id, "public_key_data"].pack('a32c1N1a16na*a*')
      end

      it "raises AppIdentityError" do
        expect { validator.validate(auth_data_with_nonzero_sign_count, key_id) }.to raise_error(
          IosAppAttest::AppIdentityError,
          /Sign counter must be zero for initial attestation/
        )
      end
    end

    context "when AAGUID is invalid" do
      let(:auth_data_with_invalid_aaguid) do
        flags = 0
        invalid_aaguid = "invalid_aaguid\x00\x00"
        credential_id_length = credential_id.bytesize
        
        [app_id_hash, flags, sign_count, invalid_aaguid, credential_id_length, credential_id, "public_key_data"].pack('a32c1N1a16na*a*')
      end

      it "raises AppIdentityError" do
        expect { validator.validate(auth_data_with_invalid_aaguid, key_id) }.to raise_error(
          IosAppAttest::AppIdentityError,
          /Invalid AAGUID for App Attestation/
        )
      end
    end

    context "when credential ID doesn't match key ID" do
      let(:invalid_key_id) { "invalid_key_id" }

      it "raises AppIdentityError" do
        expect { validator.validate(auth_data, invalid_key_id) }.to raise_error(
          IosAppAttest::AppIdentityError,
          /Credential ID does not match key ID/
        )
      end
    end
  end

  describe "private methods" do
    describe "#unpack_auth_data" do
      it "correctly unpacks auth_data" do
        rp_id_hash, unpacked_sign_count, unpacked_aaguid, unpacked_credential_id = validator.send(:unpack_auth_data, auth_data)
        
        expect(rp_id_hash).to eq(app_id_hash)
        expect(unpacked_sign_count).to eq(sign_count)
        expect(unpacked_aaguid).to eq(aaguid)
        expect(unpacked_credential_id).to eq(credential_id)
      end
    end

    describe "#validate_aaguid" do
      it "returns true for valid production AAGUID" do
        expect(validator.send(:validate_aaguid, "appattest\x00\x00\x00\x00\x00\x00\x00")).to be true
      end

      context "in development environment" do
        before do
          allow(ENV).to receive(:[]).with('IOS_APP_ATTEST_ENV').and_return('development')
        end

        it "returns true for development AAGUID" do
          expect(validator.send(:validate_aaguid, "appattestdevelop")).to be true
        end

        it "returns true for production AAGUID" do
          expect(validator.send(:validate_aaguid, "appattest\x00\x00\x00\x00\x00\x00\x00")).to be true
        end

        it "returns false for invalid AAGUID" do
          expect(validator.send(:validate_aaguid, "invalid_aaguid")).to be false
        end
      end

      context "in production environment" do
        before do
          allow(ENV).to receive(:[]).with('IOS_APP_ATTEST_ENV').and_return('production')
        end

        it "returns false for development AAGUID" do
          expect(validator.send(:validate_aaguid, "appattestdevelop")).to be false
        end

        it "returns true for production AAGUID" do
          expect(validator.send(:validate_aaguid, "appattest\x00\x00\x00\x00\x00\x00\x00")).to be true
        end
      end
    end

    describe "#app_id" do
      it "returns app_id from configuration" do
        expect(validator.send(:app_id)).to eq("com.example.app")
      end
    end
  end
end
