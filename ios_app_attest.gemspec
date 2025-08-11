require_relative "lib/ios_app_attest/version"

Gem::Specification.new do |spec|
  spec.name          = "ios_app_attest"
  spec.version       = IosAppAttest::VERSION
  spec.authors       = ["Chaitra Mudili"]
  spec.email         = ["chaitra.mudili@gmail.com"]

  spec.summary       = "Ruby gem for iOS App Attestation verification"
  spec.description   = "A Ruby library for verifying iOS App Attestation tokens"
  spec.homepage      = "https://github.com/chaitra-mudili/ios-app-attest-ruby"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir["lib/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]

  # Dependencies
  spec.add_dependency "cbor", "~> 0.5.9"
  spec.add_dependency "openssl", "~> 3.0"
  
  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
