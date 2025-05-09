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

  describe 'when receiving a post request to /csr' do
    before :example do
      # Create a CA to sign certificates
      @common_name = 'MyCA'
      body = { common_name: @common_name }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/ca', body, env)

      @id = JSON.parse(last_response.body)['id']
    end

    it 'returns 403 Forbidden error when no API Key is provided' do
      # Send a request without the API Key
      post '/csr'

      # Expect an unauthorized error
      expect(last_response.status).to eq 403
    end

    it 'returns the certificate signed by the CA' do
      body = {
        id: @id,
        csr: <<~EOS
          -----BEGIN CERTIFICATE REQUEST-----
          MIICzTCCAbUCAQAwgYcxCzAJBgNVBAYTAkdCMRYwFAYDVQQIEw1TdGFmZm9yZHNo
          aXJlMRcwFQYDVQQHEw5TdG9rZSBvbiBUcmVudDEjMCEGA1UEChMaUmVkIEtlc3Ry
          ZWwgQ29uc3VsdGluZyBMdGQxIjAgBgNVBAMTGXRlc3RjZXJ0LnJlZGtlc3RyZWwu
          Y28udWswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWLeW88IeAIa3n
          23R99i874fh0jetf+STsGPgkfGXGJ++tclKGk3MJE0ijD4PNaxGXUCNULgn2ROyy
          bm5sTmGzpEOD+1AAAyV+pLQoFNkHEFuudGqVM6XkPWfqaM2vKvdzUbPPC0X/MfDF
          GPxc8AY3TUM385c9c9/WOIF6NUcAvAFIQF0zG7evzJZBqDb4enUnatMSLHmxRWMi
          1JeHtfLINXhNitHewEQWgIB3j1xmh7CPO5FeTb6HzQDxc+f7uMisY6s9J/Ph3GeO
          CeIDooqU8jnfV5eGEzIMH5CFMZjajrNKF4DYK3YRyUI0K66+v0KILoUntEs++M20
          LhOn+VE9AgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAUWE7oBX3SLjYNM53bsBO
          lNGnsgAp1P1fiCPpEKaZGEOUJ2xOguIHSu1N1ZigKpWmiAAZxuoagW1R/ANM3jXp
          vCLVBRv40AHCFsot9udrdCYjI43aDHAaYvLmT4/Pvpntcn0/7+g//elAHhr9UIoo
          MZwwwo6yom67Jwfw/be/g7Mae7mPHZ2lsQTS02hEeqVynIRk2W9meQULrt+/atog
          0mqJSBx0WswtHliTc+nXFpQrwFIEzVuPGCOVw7LmCfNmHNCkZVuRSJB/9MdLmrfw
          chPI3NeTGSe+BZfsOtpt2/7j+bqeYKFu8B0stLoJBEnihxUoV18uZOmOeuVuX1N6
          nA==
          -----END CERTIFICATE REQUEST-----
        EOS
      }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/csr', body, env)

      response = JSON.parse(last_response.body)
      crt = OpenSSL::X509::Certificate.new response['crt']
      expect(crt.issuer.to_s).to match(/#{@common_name}/)
    end

    it 'returns 500 if an exception is raised' do
      body = {
        id: 'Non-Existent-CA',
        csr: <<~EOS
          -----BEGIN CERTIFICATE REQUEST-----
          MIICzTCCAbUCAQAwgYcxCzAJBgNVBAYTAkdCMRYwFAYDVQQIEw1TdGFmZm9yZHNo
          aXJlMRcwFQYDVQQHEw5TdG9rZSBvbiBUcmVudDEjMCEGA1UEChMaUmVkIEtlc3Ry
          ZWwgQ29uc3VsdGluZyBMdGQxIjAgBgNVBAMTGXRlc3RjZXJ0LnJlZGtlc3RyZWwu
          Y28udWswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWLeW88IeAIa3n
          23R99i874fh0jetf+STsGPgkfGXGJ++tclKGk3MJE0ijD4PNaxGXUCNULgn2ROyy
          bm5sTmGzpEOD+1AAAyV+pLQoFNkHEFuudGqVM6XkPWfqaM2vKvdzUbPPC0X/MfDF
          GPxc8AY3TUM385c9c9/WOIF6NUcAvAFIQF0zG7evzJZBqDb4enUnatMSLHmxRWMi
          1JeHtfLINXhNitHewEQWgIB3j1xmh7CPO5FeTb6HzQDxc+f7uMisY6s9J/Ph3GeO
          CeIDooqU8jnfV5eGEzIMH5CFMZjajrNKF4DYK3YRyUI0K66+v0KILoUntEs++M20
          LhOn+VE9AgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAUWE7oBX3SLjYNM53bsBO
          lNGnsgAp1P1fiCPpEKaZGEOUJ2xOguIHSu1N1ZigKpWmiAAZxuoagW1R/ANM3jXp
          vCLVBRv40AHCFsot9udrdCYjI43aDHAaYvLmT4/Pvpntcn0/7+g//elAHhr9UIoo
          MZwwwo6yom67Jwfw/be/g7Mae7mPHZ2lsQTS02hEeqVynIRk2W9meQULrt+/atog
          0mqJSBx0WswtHliTc+nXFpQrwFIEzVuPGCOVw7LmCfNmHNCkZVuRSJB/9MdLmrfw
          chPI3NeTGSe+BZfsOtpt2/7j+bqeYKFu8B0stLoJBEnihxUoV18uZOmOeuVuX1N6
          nA==
          -----END CERTIFICATE REQUEST-----
        EOS
      }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/csr', body, env)

      expect(last_response.status).to eq 500
    end

    it 'returns 500 if a the body is not a valid JSON document' do
      env = {
        'CONTENT_TYPE' => 'application/json',
        'X-API-Key' => 'TEST_API_KEY'
      }
      post('/csr', 'Not JSON', env)

      expect(last_response.status).to eq 400
    end
  end
end
