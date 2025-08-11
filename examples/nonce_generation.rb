#!/usr/bin/env ruby
# frozen_string_literal: true

# This example demonstrates how to use the NonceGenerator to generate nonces for iOS App Attest

require "bundler/setup"
require "ios_app_attest"
require "redis"
require "logger"

# Configure the IosAppAttest gem
IosAppAttest.configure do |config|
  # Your Apple Team ID and Bundle ID
  config.app_id = "TEAM_ID.BUNDLE_ID"
  
  # Encryption key for nonce encryption/decryption
  # In a real application, you would use a secure environment variable
  config.encryption_key = ENV["IOS_APP_ATTEST_TOKEN"] || "0" * 32
end

# Note: The Apple App Attestation OID is hardcoded in the gem as "1.2.840.113635.100.8.2"

# Create a Redis client
redis = Redis.new(url: ENV["REDIS_URL"] || "redis://localhost:6379/0")

# Create a logger
logger = Logger.new(STDOUT)
logger.level = Logger::INFO

# Create a nonce generator with Redis client
nonce_generator = IosAppAttest::NonceGenerator.new(
  redis_client: redis,
  logger: logger,
  expiry_seconds: 300 # 5 minutes expiry
)

begin
  # Generate a nonce
  nonce_data = nonce_generator.generate
  
  puts "Nonce generated successfully!"
  puts "Challenge ID: #{nonce_data[:challenge_nonce_id]}"
  puts "Encrypted Challenge: #{nonce_data[:challenge_nonce]}"
  puts "Initialization Vector: #{nonce_data[:initialization_vector]}"
  
  # In a real application, you would return this data to the client
  # The client would use this data to generate an attestation object
  # The attestation object would then be sent back to the server for verification
rescue IosAppAttest::NonceGenerator::NonceGenerationError => e
  puts "Nonce generation failed: #{e.message}"
end
