# frozen_string_literal: true

require "spec_helper"

RSpec.describe IosAppAttest::Validators::Utils do
  describe ".decode_base64" do
    it "decodes a base64 string" do
      encoded = "SGVsbG8gV29ybGQ="
      expect(described_class.decode_base64(encoded)).to eq("Hello World")
    end
  end
end
