# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::CertificateValidator do
  let(:config) { double("Configuration") }
  let(:logger) { double("Logger", error: nil) }
  let(:validator) { described_class.new(config, logger: logger) }

  let(:mock_cred_cert) { instance_double(OpenSSL::X509::Certificate) }
  let(:mock_chain_cert) { instance_double(OpenSSL::X509::Certificate) }
  let(:mock_extension) { instance_double(OpenSSL::X509::Extension, oid: "1.2.840.113635.100.8.2", to_der: "extension_der_data") }
  let(:mock_public_key) { instance_double(OpenSSL::PKey::RSA, to_der: "public_key_der_data") }
  
  let(:mock_asn1_sequence) do
    double('ASN1Sequence', tag: OpenSSL::ASN1::SEQUENCE, value: [1]) # Size 1 array
  end
  
  let(:mock_asn1_value) do
    double('ASN1Value', value: [nil, mock_asn1_value2])
  end
  
  let(:mock_asn1_value2) do
    double('ASN1Value2', value: "inner_value")
  end

  let(:valid_attestation) do
    {
      'attStmt' => {
        'x5c' => ["cert_data1", "cert_data2"]
      }
    }
  end

  before do
    # Mock certificate creation
    allow(OpenSSL::X509::Certificate).to receive(:new).with("cert_data1").and_return(mock_cred_cert)
    allow(OpenSSL::X509::Certificate).to receive(:new).with("cert_data2").and_return(mock_chain_cert)
    # Mock the hardcoded root CA certificate
    allow(OpenSSL::X509::Certificate).to receive(:new).with(instance_of(String)).and_return(mock_chain_cert)
    
    # Mock certificate store
    mock_store = instance_double(OpenSSL::X509::Store)
    allow(mock_store).to receive(:add_cert).and_return(mock_store)
    allow(OpenSSL::X509::Store).to receive(:new).and_return(mock_store)
    
    # Mock store context
    mock_context = instance_double(OpenSSL::X509::StoreContext)
    allow(OpenSSL::X509::StoreContext).to receive(:new).and_return(mock_context)
    allow(mock_context).to receive(:verify).and_return(true)
    
    # Mock certificate extensions
    allow(mock_cred_cert).to receive(:extensions).and_return([mock_extension])
    allow(mock_cred_cert).to receive(:public_key).and_return(mock_public_key)
    
    # Mock ASN1 decoding
    allow(OpenSSL::ASN1).to receive(:decode).with("extension_der_data").and_return(mock_asn1_value)
    allow(OpenSSL::ASN1).to receive(:decode).with("inner_value").and_return(mock_asn1_sequence)
  end

  describe "#validate" do
    it "validates the certificate chain and app attest OID" do
      # Allow verify_app_attest_oid to be called with any arguments
      expect(validator).to receive(:verify_app_attest_oid)
      
      # Just verify the method runs without error
      expect { validator.validate(valid_attestation) }.not_to raise_error
    end

    context "when certificate chain verification fails" do
      before do
        mock_context = instance_double(OpenSSL::X509::StoreContext)
        allow(OpenSSL::X509::StoreContext).to receive(:new).and_return(mock_context)
        allow(mock_context).to receive(:verify).and_return(false)
        allow(mock_context).to receive(:error_string).and_return("Certificate verification error")
      end

      it "raises CertificateError" do
        expect { validator.validate(valid_attestation) }.to raise_error(
          IosAppAttest::CertificateError,
          /Certificate chain verification failed: Certificate verification error/
        )
      end
    end
  end

  describe "#validate_sequence" do
    it "passes with valid sequence structure" do
      expect { validator.validate_sequence(mock_cred_cert) }.not_to raise_error
    end

    context "when sequence structure is invalid" do
      let(:mock_asn1_sequence) do
        double('ASN1Sequence', tag: OpenSSL::ASN1::SEQUENCE, value: [1, 2]) # Size > 1 array
      end

      it "raises VerificationError" do
        expect { validator.validate_sequence(mock_cred_cert) }.to raise_error(
          IosAppAttest::CertificateError,
          /Failed sequence structure validation/
        )
      end
    end

    context "when tag is not a sequence" do
      let(:mock_asn1_sequence) do
        double('ASN1Sequence', tag: OpenSSL::ASN1::INTEGER, value: [1]) # Not a sequence
      end

      it "raises VerificationError" do
        expect { validator.validate_sequence(mock_cred_cert) }.to raise_error(
          IosAppAttest::CertificateError,
          /Failed sequence structure validation/
        )
      end
    end
  end

  describe "#extract_public_key" do
    it "returns the public key in DER format" do
      expect(validator.extract_public_key(mock_cred_cert)).to eq("public_key_der_data")
    end
  end

  describe "private methods" do
    describe "#verify_app_attest_oid" do
      it "passes when certificate has the app attest OID" do
        expect { validator.send(:verify_app_attest_oid, mock_cred_cert) }.not_to raise_error
      end

      context "when certificate is missing the app attest OID" do
        before do
          allow(mock_extension).to receive(:oid).and_return("different.oid")
        end

        it "raises CertificateError" do
          expect { validator.send(:verify_app_attest_oid, mock_cred_cert) }.to raise_error(
            IosAppAttest::CertificateError,
            /Missing App Attest OID in certificate/
          )
        end
      end
    end

    describe "#root_ca" do
      it "returns hardcoded root CA" do
        expect(validator.send(:root_ca)).to be_a(String)
        expect(validator.send(:root_ca)).to include("BEGIN CERTIFICATE")
      end
    end

    describe "#app_attest_oid" do
      it "returns hardcoded App Attest OID constant" do
        expect(validator.send(:app_attest_oid)).to eq(described_class::APP_ATTEST_OID)
      end
    end
  end
end
