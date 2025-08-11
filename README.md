# iOS App Attest

A Ruby gem for verifying iOS App Attest tokens - Apple's device attestation mechanism for iOS apps.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ios_app_attest'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install ios_app_attest
```

## Usage

### Configuration

Configure the gem with your app's specific settings:

```ruby
IosAppAttest.configure do |config|
  config.app_id = "TEAM_ID.BUNDLE_ID" # Your Apple Team ID and Bundle ID
  config.encryption_key = ENV.fetch("IOS_APP_ATTEST_TOKEN").byteslice(0, 32) # Your encryption key (32 bytes)
end
```

> Note: The Apple App Attestation root CA certificate and App Attest OID ("1.2.840.113635.100.8.2") are now hardcoded in the gem for security and convenience.

### Complete Attestation Flow

#### 1. Generating and Storing Challenge Nonces

When a client requests a nonce, your server generates it and stores it in Redis with a TTL:

```ruby
# Create a Redis client for nonce storage
redis = Redis.new(url: ENV["REDIS_URL"] || "redis://localhost:6379/0")

# Create a nonce generator
nonce_generator = IosAppAttest::NonceGenerator.new(
  redis_client: redis,
  logger: Rails.logger, # Optional
  expiry_seconds: 300 # Optional: Nonce expiry time in seconds (default: 120)
)

# Generate a nonce (this also stores it in Redis with the configured TTL)
nonce_data = nonce_generator.generate

# The nonce_data contains:
# - challenge_nonce_id: A unique identifier for the challenge (used as Redis key)
# - challenge_nonce: The encrypted challenge nonce (base64 encoded)
# - initialization_vector: The IV used for encryption (base64 encoded)

# Send this data to the client for attestation
```

#### 2. Client-Side Processing

```
# On the client side (iOS app):
# 1. Receive the nonce data from the server
# 2. Decrypt the challenge_nonce using the same encryption key:
#    a. Base64 decode the challenge_nonce and initialization_vector
#    b. Use AES-256-CBC with the shared encryption key to decrypt the challenge
# 3. Use the decrypted nonce in the App Attestation process
# 4. Send the attestation object back to the server along with the original nonce data
```

#### 3. Server-Side Verification

When the client sends back the attestation object along with the original nonce data, the server:

```ruby
# Attestation parameters from the client
attestation_params = {
  attestation_object: "base64_encoded_attestation_object",
  key_id: "base64_encoded_key_id",
  challenge_nonce: "base64_encoded_challenge", # The encrypted challenge nonce (base64 encoded)
  initialization_vector: "base64_encoded_initialization_vector", # The IV used for encryption (base64 encoded)
  challenge_nonce_id: "challenge_id" # The unique identifier for the challenge
}

# Create a verifier with Redis client for nonce verification
verifier = IosAppAttest::Verifier.new(
  attestation_params,
  redis_client: redis, # Redis client for nonce verification (required for TTL check)
  logger: Rails.logger # Optional: Logger for error logging
)

begin
  # Verify the attestation - this process includes:
  # 1. Decrypting the challenge nonce using the encryption key
  # 2. Checking if the nonce exists in Redis (validates TTL)
  # 3. Validating the attestation structure and certificates
  # 4. Verifying the nonce matches what was used in the attestation
  public_key, receipt = verifier.verify
  
  # Use the public_key and receipt for further processing
  # e.g., store the public_key for future authentications
rescue IosAppAttest::CertificateError => e
  # Handle certificate validation errors
  puts "Certificate validation failed: #{e.message}"
rescue IosAppAttest::ChallengeError => e
  # Handle challenge validation errors
  puts "Challenge validation failed: #{e.message}"
rescue IosAppAttest::AttestationError => e
  # Handle attestation format errors
  puts "Attestation format invalid: #{e.message}"
rescue IosAppAttest::AppIdentityError => e
  # Handle app identity validation errors
  puts "App identity validation failed: #{e.message}"
rescue IosAppAttest::NonceError => e
  # Handle nonce validation errors
  puts "Nonce validation failed: #{e.message}"
rescue IosAppAttest::VerificationError => e
  # Handle other verification errors
  puts "Verification failed: #{e.message}"
end
```

### Complete Flow

Here's the complete flow for implementing iOS App Attestation in your application:

1. **Server-side**: Generate a challenge nonce
   ```ruby
   nonce_data = nonce_generator.generate
   # Returns: { challenge_nonce_id:, challenge_nonce:, initialization_vector: }
   ```

2. **Send to Client**: Send the nonce data to your iOS client

3. **Client-side**: The iOS client uses the nonce to generate an attestation using Apple's DeviceCheck framework
   ```swift
   // Swift code (client-side)
   let service = DCAppAttestService.shared
   if service.isSupported {
     // Generate a new key pair
     service.generateKey { keyId, error in
       // Use the keyId and challenge to generate an attestation
       service.attestKey(keyId, clientDataHash: challengeHash) { attestation, error in
         // Send attestation, keyId, and challenge data back to server
       }
     }
   }
   ```

4. **Server-side**: Verify the attestation
   ```ruby
   verifier = IosAppAttest::Verifier.new(
     attestation_params,
     redis_client: redis
   )
   
   public_key, receipt = verifier.verify
   # Store the public_key for future authentications
   ```

5. **Future Assertions**: For subsequent requests, the client generates assertions that can be verified using the stored public key

### Parameter Reference

The library uses the following parameter names:

| Parameter Name | Description |
|----------------|-------------|
| `challenge_nonce_id` | Unique identifier for the challenge nonce |
| `challenge_nonce` | Base64-encoded encrypted challenge nonce |
| `initialization_vector` | Base64-encoded initialization vector used for encryption |
| `attestation_object` | Base64-encoded attestation object from Apple's DeviceCheck framework |
| `key_id` | Base64-encoded key ID generated by the client |


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/chaitra-mudili/ios-app-attest-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
