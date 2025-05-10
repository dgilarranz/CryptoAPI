# frozen_string_literal: true
# Load environment variables
require 'dotenv'
Dotenv.load!

require_relative 'lib/crypto_api'

# Use standard protection to prevent common attacks
require 'rack/protection'
use Rack::Protection

run CryptoAPI::App
