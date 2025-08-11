#!/usr/bin/env ruby
# frozen_string_literal: true

# This example demonstrates basic usage of the AppAttestation gem

require "bundler/setup"
require "ios_app_attest"
require "redis"

# Configure the IosAppAttest gem
IosAppAttest.configure do |config|
  # Your Apple Team ID and Bundle ID
  config.app_id = "TEAM_ID.BUNDLE_ID"
  
  # Your encryption key (first 32 bytes)
  config.encryption_key = ENV.fetch("IOS_APP_ATTEST_TOKEN").byteslice(0, 32)
end

# Note: The Apple App Attestation OID is hardcoded in the gem as "1.2.840.113635.100.8.2"

# Mock attestation parameters (in a real app, these would come from the client)
attestation_params = {
  attestation_object: "base64_encoded_attestation_object",
  key_id: "base64_encoded_key_id",
  challenge_nonce: "base64_encoded_challenge",
  initialization_vector: "base64_encoded_initialization_vector",
  challenge_nonce_id: "challenge_id"
}

# Initialize Redis client for nonce verification
redis = Redis.new(url: ENV["REDIS_URL"] || "redis://localhost:6379/0")

# Create a verifier with Redis client for nonce verification
verifier = IosAppAttest::Verifier.new(
  attestation_params,
  redis_client: redis,
  logger: Logger.new(STDOUT)
)

begin
  # Verify the attestation
  public_key, receipt = verifier.verify
  
  puts "Verification successful!"
  puts "Public key: #{public_key.unpack('H*').first}"
  puts "Receipt length: #{receipt.length} bytes"
  
  # In a real application, you would store the public_key for future authentications
  # and potentially validate the receipt with Apple's servers
rescue IosAppAttest::Verifier::VerificationError => e
  puts "Verification failed: #{e.message}"
end
