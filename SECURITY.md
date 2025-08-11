# Security Policy

## Supported Versions

Currently, we provide security updates for the following versions of the iOS App Attest Ruby gem:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of iOS App Attest Ruby gem seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly**
2. **Email the maintainers directly** at [security@example.com](mailto:security@example.com) with details about the vulnerability
3. Include the following information:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Considerations

The iOS App Attest Ruby gem handles cryptographic operations and sensitive attestation data. Please consider the following security best practices:

### Error Handling

- The gem provides specific error subclasses for different validation failures
- Use these specific error classes in your application to handle different error scenarios appropriately
- Log validation failures for security monitoring and auditing purposes

### Encryption Key Management

- Store your encryption keys securely, preferably in a key management service
- Never hardcode encryption keys in your application code
- Rotate encryption keys periodically

### Nonce Validation

- The gem automatically deletes nonces after successful validation to prevent replay attacks
- Configure appropriate expiry times for nonces based on your application's needs

### Certificate Validation

- The gem validates Apple's App Attestation certificates against the provided root CA
- Keep your root CA certificate up to date

### Redis Security

If using Redis for nonce storage:

- Secure your Redis instance with authentication
- Use TLS for Redis connections in production
- Consider using Redis with persistence for important nonces

## Dependencies

We regularly review and update our dependencies to address security vulnerabilities. If you're using this gem, we recommend:

- Keeping the gem updated to the latest version
- Monitoring your dependency tree for security advisories
- Running security scans on your application code

## Secure Development

This gem follows secure development practices:

- All cryptographic operations use industry-standard libraries and algorithms
- We use AES-256-CBC for encryption
- We validate all cryptographic signatures and certificates
- We follow the principle of least privilege in our code

## Disclosure Policy

- We will acknowledge receipt of your vulnerability report within 48 hours
- We will provide an initial assessment of the vulnerability within 7 days
- We aim to release a fix for verified vulnerabilities within 30 days
- We will credit reporters who follow responsible disclosure practices
