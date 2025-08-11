# frozen_string_literal: true

# Error classes for iOS App Attest verification
#
# This file defines a hierarchy of error classes for the iOS App Attest verification process.
# The hierarchy is designed to allow for specific error handling based on the type of error
# that occurred during verification.
#
# The main error categories are:
# - ConfigurationError: For configuration-related errors
# - VerificationError: Base class for all verification errors
#   - NonceError: For nonce-related errors
#   - CertificateError: For certificate-related errors
#   - ChallengeError: For challenge-related errors
#   - AppIdentityError: For app identity-related errors
#   - AttestationError: For attestation format-related errors
#
# Each category has specific subclasses for more granular error handling.
#
module IosAppAttest
  # Base error class for all IosAppAttest errors
  class Error < StandardError; end

  # Error raised when configuration is invalid or incomplete
  #
  # This error is raised when the configuration object is missing required
  # parameters or contains invalid values.
  class ConfigurationError < Error; end

  # Error raised when attestation verification fails
  #
  # This is the base class for all verification-related errors.
  # More specific error subclasses should be used when possible.
  class VerificationError < Error; end

  # Error raised when nonce validation fails
  #
  # This error is raised when there are issues with the challenge nonce
  # during the verification process, such as expired, already used,
  # or not found nonces.
  class NonceError < VerificationError
    # Error raised when a nonce has expired
    class Expired < NonceError; end
    
    # Error raised when a nonce has already been used
    class AlreadyUsed < NonceError; end
    
    # Error raised when a nonce is not found
    class NotFound < NonceError; end
  end

  # Error raised when certificate validation fails
  #
  # This error is raised when there are issues with the certificate
  # during the verification process, such as invalid chain, expired certificate,
  # or invalid certificate structure.
  class CertificateError < VerificationError
    # Error raised when certificate chain validation fails
    class ChainInvalid < CertificateError; end
    
    # Error raised when certificate has expired
    class Expired < CertificateError; end
    
    # Error raised when certificate is not yet valid
    class NotYetValid < CertificateError; end
    
    # Error raised when certificate structure is invalid
    class InvalidStructure < CertificateError; end
  end

  # Error raised when challenge validation fails
  #
  # This error is raised when there are issues with the challenge
  # during the verification process, such as invalid signature,
  # invalid format, or key ID mismatch.
  class ChallengeError < VerificationError
    # Error raised when challenge signature is invalid
    class InvalidSignature < ChallengeError; end
    
    # Error raised when challenge format is invalid
    class InvalidFormat < ChallengeError; end
    
    # Error raised when key ID doesn't match
    class KeyIdMismatch < ChallengeError; end
  end

  # Error raised when app identity validation fails
  #
  # This error is raised when there are issues with the app identity
  # during the verification process, such as ID mismatch or invalid format.
  class AppIdentityError < VerificationError
    # Error raised when app ID doesn't match
    class IdMismatch < AppIdentityError; end
    
    # Error raised when app identity format is invalid
    class InvalidFormat < AppIdentityError; end
  end

  # Error raised when attestation format is invalid
  #
  # This error is raised when there are issues with the attestation format
  # during the verification process, such as invalid structure or missing data.
  class AttestationError < VerificationError
    # Error raised when attestation structure is invalid
    class InvalidStructure < AttestationError; end
    
    # Error raised when attestation data is missing
    class MissingData < AttestationError; end
  end
end
