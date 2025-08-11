# iOS App Attest Usage Guide

This document provides detailed information on how to use the iOS App Attest gem for verifying iOS App Attestation tokens.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Basic Usage](#basic-usage)
4. [Advanced Usage](#advanced-usage)
5. [Error Handling](#error-handling)
6. [Integration with Rails](#integration-with-rails)
7. [Integration with Other Frameworks](#integration-with-other-frameworks)

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

## Configuration

Before using the iOS App Attest gem, you need to configure it with your app's specific settings:

```ruby
IosAppAttest.configure do |config|
  # Your Apple Team ID and Bundle ID combined
  config.app_id = "TEAM_ID.BUNDLE_ID"
  
  # Your encryption key (first 32 bytes of your secret key)
  config.encryption_key = ENV.fetch("IOS_APP_ATTEST_TOKEN").byteslice(0, 32)
end
```

> **Note:** The Apple App Attestation root CA certificate and App Attest OID ("1.2.840.113635.100.8.2") are now hardcoded in the gem for security and convenience.

### Configuration Options

| Option | Description | Required |
|--------|-------------|----------|
| `app_id` | Your Apple Team ID and Bundle ID combined (e.g., "ABCDE12345.com.example.app") | Yes |
| `encryption_key` | Your encryption key (32 bytes) | Yes |

## Basic Usage

## Complete Attestation Flow

### 1. Generating and Storing Challenge Nonces

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

# Generate a nonce - this also stores the nonce in Redis with the specified TTL
nonce_data = nonce_generator.generate

# The nonce_data contains:
# - challenge_nonce_id: A unique identifier for the challenge (used as Redis key)
# - challenge_nonce: The encrypted challenge nonce (base64 encoded)
# - initialization_vector: The IV used for encryption (base64 encoded)

# Send this data to the client for attestation
```

### 2. Client-Side Processing

```
# On the client side (iOS app):
# 1. Request a nonce from your server
# 2. Receive the nonce data (challenge_nonce_id, challenge_nonce, initialization_vector)
# 3. Decrypt the challenge_nonce using the same encryption key:
#    a. Base64 decode the challenge_nonce and initialization_vector
#    b. Use AES-256-CBC with the shared encryption key to decrypt the challenge
# 4. Use the decrypted nonce in the App Attestation process
# 5. Send the attestation object back to the server along with the original nonce data
```

### 3. Server-Side Verification with Redis TTL Validation

When the client sends back the attestation object along with the original nonce data, the server performs these steps:

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
  logger: Logger.new(STDOUT) # Optional: Logger for error logging
)

begin
  # Verify the attestation - this process includes:
  # 1. Decrypting the challenge nonce using the encryption key
  # 2. Checking if the nonce exists in Redis (validates TTL)
  #    - If the nonce has expired or doesn't exist, validation fails
  #    - This ensures attestation objects can't be reused after TTL expires
  # 3. Validating the attestation structure and certificates
  # 4. Verifying the nonce matches what was used in the attestation
  public_key, receipt = verifier.verify
  
  # Use the public_key and receipt for further processing
  # e.g., store the public_key for future authentications
rescue IosAppAttest::Verifier::VerificationError => e
  # Handle verification failure
  puts "Verification failed: #{e.message}"
end
```

## Advanced Usage

### Using Redis for Nonce Verification

```ruby
# Initialize Redis client
redis = Redis.new(url: ENV["REDIS_URL"])

# Create a verifier with Redis client
verifier = IosAppAttest::Verifier.new(
  attestation_params,
  redis_client: redis
)

# Verify the attestation
public_key, receipt = verifier.verify
```

### Adding Logging

```ruby
# Create a verifier with a logger
verifier = IosAppAttest::Verifier.new(
  attestation_params,
  logger: Rails.logger # or any Logger instance
)

# Verify the attestation
public_key, receipt = verifier.verify
```

## Error Handling

The `verify` method can raise a `VerificationError` if any part of the attestation verification fails. It's important to handle these errors appropriately:

```ruby
begin
  public_key, receipt = verifier.verify
  # Verification successful
rescue IosAppAttest::Verifier::VerificationError => e
  # Handle specific verification errors
  case e.message
  when /Invalid nonce/
    # Handle invalid nonce error
  when /Certificate chain verification failed/
    # Handle certificate chain verification error
  else
    # Handle other verification errors
  end
end
```

## Integration with Rails

### In a Controller

```ruby
class ProfilesController < ApplicationController
  def create
    attestation_params = params.require(:attestation).permit(:attestation_object, :key_id, :challenge_nonce, :initialization_vector, :challenge_nonce_id)
    
    verifier = IosAppAttest::Verifier.new(
      attestation_params,
      redis_client: $redis,
      logger: Rails.logger
    )
    
    begin
      public_key, receipt = verifier.verify
      # Continue with profile creation
    rescue IosAppAttest::Verifier::VerificationError => e
      render json: { error: "Attestation verification failed" }, status: :unprocessable_entity
    end
  end
end
```

### In an Interactor

```ruby
class VerifyAppAttestation
  include Interactor
  
  def call
    return unless context.attestation_params.present?
    
    verifier = IosAppAttest::Verifier.new(
      context.attestation_params,
      redis_client: $redis,
      logger: Rails.logger
    )
    
    begin
      context.public_key, context.receipt = verifier.verify
    rescue IosAppAttest::Verifier::VerificationError => e
      context.fail!(error: "Please try again after sometime.")
    end
  end
end
```

## Integration with Other Frameworks

The App Attestation gem is framework-agnostic and can be used with any Ruby application. Simply configure the gem and use the `Verifier` class as shown in the examples above.
