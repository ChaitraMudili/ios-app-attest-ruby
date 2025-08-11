# frozen_string_literal: true

module IosAppAttest
  module Validators
    # Validates certificate chain and related aspects
    #
    # This validator is responsible for verifying the certificate chain,
    # validating sequence structures, and ensuring the App Attest OID
    # is present in the certificate.
    #
    # @example
    #   validator = IosAppAttest::Validators::CertificateValidator.new(config)
    #   cred_cert = validator.validate(attestation)
    class CertificateValidator < BaseValidator
      # Validate the certificate chain
      #
      # This method performs the following validations:
      # 1. Extracts certificates from the attestation statement
      # 2. Verifies the certificate chain against the Apple root CA
      # 3. Validates that the certificate contains the App Attest OID
      #
      # @param attestation [Hash] The decoded attestation object containing x5c certificates
      # @return [OpenSSL::X509::Certificate] The credential certificate if validation succeeds
      # @raise [IosAppAttest::CertificateError] If certificate chain validation fails or App Attest OID is missing
      def validate(attestation)
        att_stmt = attestation['attStmt']
        certificates = att_stmt['x5c'].map { |c| OpenSSL::X509::Certificate.new(c) }
        cred_cert, *chain = certificates
        
        context = OpenSSL::X509::StoreContext.new(certificates_store, cred_cert, chain)
        unless context.verify
          raise IosAppAttest::CertificateError, 
                "Certificate chain verification failed: #{context.error_string}"
        end
        
        verify_app_attest_oid(cred_cert)
        cred_cert
      end
      
      # Validate the sequence structure in the certificate
      #
      # This method validates that the certificate extension with the App Attest OID
      # contains a properly structured ASN.1 sequence. This is required for the
      # challenge validation process.
      #
      # @param cred_cert [OpenSSL::X509::Certificate] The credential certificate to validate
      # @raise [IosAppAttest::CertificateError] If sequence structure validation fails
      def validate_sequence(cred_cert)
        extension = cred_cert.extensions.find { |e| e.oid == app_attest_oid }
        sequence = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value[1].value)
        
        unless sequence.tag == OpenSSL::ASN1::SEQUENCE && sequence.value.size == 1
          raise IosAppAttest::CertificateError, 'Failed sequence structure validation'
        end
      end
      
      # Extract the public key from the certificate
      #
      # This method extracts the public key from the credential certificate
      # in DER (Distinguished Encoding Rules) format for further validation.
      #
      # @param cred_cert [OpenSSL::X509::Certificate] The credential certificate
      # @return [String] The public key in DER format
      def extract_public_key(cred_cert)
        cred_cert.public_key.to_der
      end
      
      private
      
      # Validate the app attest OID in the certificate
      #
      # This method checks that the certificate contains the Apple App Attest OID
      # extension, which is required for valid App Attestation certificates.
      #
      # @param certificate [OpenSSL::X509::Certificate] The certificate to validate
      # @raise [IosAppAttest::CertificateError] If App Attest OID is missing
      def verify_app_attest_oid(certificate)
        has_oid = certificate.extensions.any? { |ext| ext.oid == app_attest_oid }
        unless has_oid
          raise IosAppAttest::CertificateError, "Missing App Attest OID in certificate"
        end
      end
      
      # Create certificates store with hardcoded root CA
      #
      # This method creates an OpenSSL certificate store and adds the hardcoded Apple
      # root CA certificate to it for certificate chain validation.
      #
      # @return [OpenSSL::X509::Store] The certificate store with Apple root CA
      def certificates_store
        root_cert = OpenSSL::X509::Certificate.new(root_ca)
        @certificates_store ||= OpenSSL::X509::Store.new.add_cert(root_cert)
      end
      
      # Get hardcoded root CA 
      #
      # This method returns the hardcoded Apple App Attestation root CA certificate content.
      # The certificate is stored as a constant to avoid recreating the string on each call.
      #
      # @return [String] The Apple root CA certificate content
      # @raise [IosAppAttest::CertificateError] If the certificate format is invalid
      def root_ca
        APPLE_APP_ATTEST_ROOT_CA
      rescue StandardError => e
        raise IosAppAttest::CertificateError, "Invalid root CA certificate format: #{e.message}"
      end
      
      # Apple App Attestation Root CA Certificate
      # This is the official Apple App Attestation root CA certificate
      APPLE_APP_ATTEST_ROOT_CA = <<~CERT
      -----BEGIN CERTIFICATE-----
      MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
      JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
      QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
      Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
      biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
      bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
      NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
      Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
      MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
      CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
      53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
      oyFraWVIyd/dganmrduC1bmTBGwD
      -----END CERTIFICATE-----
      CERT
      
      # Apple App Attestation OID constant
      # This OID identifies the App Attest extension in certificates
      APP_ATTEST_OID = "1.2.840.113635.100.8.2"
      
      # Get app attest OID
      #
      # This method returns the hardcoded Apple App Attest OID.
      # The OID is used to identify the App Attest extension in certificates.
      #
      # @return [String] The Apple App Attest OID ("1.2.840.113635.100.8.2")
      def app_attest_oid
        APP_ATTEST_OID
      end
    end
  end
end
