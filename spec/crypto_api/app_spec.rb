require_relative '../spec_helper'

require 'rack/test'

describe 'The CryptoAPI microservice' do
  include Rack::Test::Methods

  def app
    CryptoAPI::App.new
  end

  describe 'when receiving a post request to /ca' do
    it 'returns 403 Forbidden error when no API Key is provided' do
      # Send a request without the API Key
      post('/ca', { common_name: 'MyCA' }.to_json, 'CONTENT_TYPE' => 'application/json')

      # Expect an unauthorized error
      expect(last_response.status).to eq 403
    end

    it 'returns the UUID of the generated CA' do
      body = { common_name: 'MyCA' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/ca', body, env)

      response = JSON.parse(last_response.body)
      expect(response['id']).to match(/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/)
    end

    it 'returns the certificate of the generated CA' do
      common_name = 'MyCA'
      body = { common_name: common_name }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/ca', body, env)

      response = JSON.parse(last_response.body)
      root_crt = OpenSSL::X509::Certificate.new response['crt']
      expect(root_crt.subject.to_s).to match(/#{common_name}/)
    end

    it 'returns 500 if an exception is raised' do
      body = { common_name: 'INVALID_CN/ERROR' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/ca', body, env)

      expect(last_response.status).to eq 500
    end

    it 'returns 400 if a the body is not a valid JSON document' do
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/ca', 'Not JSON', env)

      expect(last_response.status).to eq 400
    end
  end
end
