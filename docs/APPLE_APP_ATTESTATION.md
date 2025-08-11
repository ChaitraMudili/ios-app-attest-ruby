# Understanding Apple App Attestation

This document provides an overview of Apple's App Attestation process and how this gem implements the verification.

## Overview

Apple's App Attestation is a security feature that helps verify that requests to your server come from authentic instances of your app running on genuine Apple devices. It uses cryptographic attestation to establish trust between your app and your server.

## How App Attestation Works

1. **Initial Attestation**: Your app generates a key pair and requests an attestation from Apple's servers.
2. **Challenge-Response**: Your server issues a challenge that the app must sign with its private key.
3. **Verification**: Your server verifies the attestation and the signed challenge.

## Attestation Flow

```
┌─────────┐                ┌──────┐                ┌──────────────┐
│ iOS App │                │ API  │                │ Apple Server │
└────┬────┘                └──┬───┘                └──────┬───────┘
     │                        │                           │
     │ 1. Request Challenge   │                           │
     │───────────────────────>│                           │
     │                        │                           │
     │ 2. Challenge & Nonce   │                           │
     │<───────────────────────│                           │
     │                        │                           │
     │ 3. Generate Key Pair   │                           │
     │────────┐               │                           │
     │        │               │                           │
     │<───────┘               │                           │
     │                        │                           │
     │ 4. Request Attestation │                           │
     │──────────────────────────────────────────────────->│
     │                        │                           │
     │ 5. Attestation Object  │                           │
     │<──────────────────────────────────────────────────│
     │                        │                           │
     │ 6. Send Attestation    │                           │
     │───────────────────────>│                           │
     │                        │                           │
     │                        │ 7. Verify Attestation     │
     │                        │──────────┐                │
     │                        │          │                │
     │                        │<─────────┘                │
     │                        │                           │
     │ 8. Success/Failure     │                           │
     │<───────────────────────│                           │
     │                        │                           │
```

## Attestation Object Structure

The attestation object is a CBOR-encoded data structure with the following components:

- **fmt**: Format identifier (always "apple-appattest" for App Attestation)
- **attStmt**: Attestation statement containing:
  - **x5c**: Certificate chain
  - **receipt**: Receipt from Apple's servers
- **authData**: Authenticator data containing:
  - RP ID Hash (32 bytes)
  - Flags (1 byte)
  - Sign Count (4 bytes)
  - AAGUID (16 bytes)
  - Credential ID Length (2 bytes)
  - Credential ID (variable length)
  - Credential Public Key (variable length)

## Verification Steps

This gem implements the following verification steps:

1. **Nonce Validation**: Ensures the challenge nonce matches what was issued.
2. **Attestation Structure Validation**: Checks that the attestation object has the required fields.
3. **Certificate Chain Validation**: Verifies the certificate chain against Apple's root CA.
4. **App Attest OID Validation**: Confirms the certificate has the App Attestation OID.
5. **Challenge Validation**: Verifies the challenge was correctly signed.
6. **Key ID Validation**: Ensures the key ID matches the public key.
7. **Sequence Validation**: Checks the ASN.1 sequence structure.
8. **App Identity Validation**: Verifies the app ID, sign counter, AAGUID, and credential ID.

## Security Considerations

- **Nonce Storage**: Use a secure, short-lived storage (like Redis) for nonces.
- **Environment Awareness**: The gem handles different validation rules for development vs. production.
- **Error Handling**: Detailed error messages help diagnose issues without exposing sensitive information.
- **Key Management**: Securely store the encryption key used for challenge decryption.

## References

- [Apple Developer Documentation: App Attest](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity)
- [WWDC 2020: Secure your app: App Attest and the DeviceCheck API](https://developer.apple.com/videos/play/wwdc2020/10096/)
- [CBOR RFC 8949](https://tools.ietf.org/html/rfc8949)
- [WebAuthn Attestation](https://www.w3.org/TR/webauthn-2/#attestation)
