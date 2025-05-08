# frozen_string_literal: true
# Load environment variables
require 'dotenv'
Dotenv.load!

# Use standard protection to prevent common attacks
require 'rack/protection'
use Rack::Protection

# Initialize PATH and run App
require_relative 'lib/crypto_api'
run CryptoAPI::App
