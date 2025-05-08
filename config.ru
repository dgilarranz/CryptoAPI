# frozen_string_literal: true

# Use standard protection to prevent common attacks
require 'rack/protection'
use Rack::Protection

# Initialize PATH and run App
$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'crypto_api'
run CryptoApi::App
