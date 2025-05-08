require_relative '../spec_helper'

require 'rack/test'

describe 'The CryptoAPI microservice' do
  include Rack::Test::Methods

  def app
    CryptoAPI::App
  end

  describe 'when receiving a post request to /ca' do
    it 'returns 403 Forbidden error when no API Key is provided' do
      # Send a request without the API Key
      post('/ca', JSON.generate({ common_name: 'MyCA' }), 'CONTENT_TYPE' => 'application/json')

      # Expect an unauthorized error
      expect(last_response.status).to eq 403
    end
  end
end
