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
      post('/crypto/ca', { common_name: 'MyCA' }.to_json, 'CONTENT_TYPE' => 'application/json')

      # Expect an unauthorized error
      expect(last_response.status).to eq 403
    end

    it 'returns the UUID of the generated CA' do
      body = { common_name: 'MyCA' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)

      response = JSON.parse(last_response.body)
      expect(response['id']).to match(/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/)
    end

    it 'returns the certificate of the generated CA' do
      common_name = 'MyCA'
      body = { common_name: common_name }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)

      response = JSON.parse(last_response.body)
      root_crt = OpenSSL::X509::Certificate.new response['crt']
      expect(root_crt.subject.to_s).to match(/#{common_name}/)
    end

    it 'returns 500 if an exception is raised' do
      # Force an error on calls to CAService
      allow(CAService).to receive(:instance).and_raise 'Error'

      # Prepare and send the request
      body = { common_name: 'MyCA' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)

      # Expect status code 500
      expect(last_response.status).to eq 500
    end

    it 'returns 400 if a the body is not a valid JSON document' do
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', 'Not JSON', env)

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
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)

      @id = JSON.parse(last_response.body)['id']
    end

    it 'returns 403 Forbidden error when no API Key is provided' do
      # Send a request without the API Key
      post '/crypto/csr'

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
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/csr', body, env)

      response = JSON.parse(last_response.body)
      crt = OpenSSL::X509::Certificate.new response['crt']
      expect(crt.issuer.to_s).to match(/#{@common_name}/)
    end

    it 'returns 500 if an exception is raised' do
      # Force an error on calls to CAService
      allow(CAService).to receive(:instance).and_raise 'Error'

      # Prepare and send the request
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
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/csr', body, env)

      # Expect status code 500
      expect(last_response.status).to eq 500
    end

    it 'returns 400 if the body is not a valid JSON document' do
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/csr', 'Not JSON', env)

      expect(last_response.status).to eq 400
    end

    it 'prevents attempts at path traversal attacks via the ID parameter' do
      body = {
        id: '../../../../../../../../../../../../../../../../../etc/passwd',
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
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/csr', body, env)

      expect(last_response.status).to eq 400
    end
  end

  describe 'when receiving a post request to /validate' do
    it 'returns 403 Forbidden error when no API Key is provided' do
      # Send a request without the API Key
      post '/crypto/validate'

      # Expect an unauthorized error
      expect(last_response.status).to eq 403
    end

    it 'returns the `true` if the certificate was signed by the CA' do
      # Step 1: Create a new CA
      body = { common_name: 'MyCA' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)
      id = JSON.parse(last_response.body)['id']

      # Step 2: Submit a certificate signing request
      body = {
        id: id,
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
      post('/crypto/csr', body, env)
      crt = JSON.parse(last_response.body)['crt']

      # Step 3: Submit a certificate validation request
      body = {
        id: id,
        crt: crt
      }.to_json
      post('/crypto/validate', body, env)

      # Expect the certificate to be valid
      valid = JSON.parse(last_response.body)['valid']
      expect(valid).to be_truthy
    end

    it 'returns the `false` if the certificate was not signed by the CA' do
      # Step 1: Create a new CA
      body = { common_name: 'MyCA' }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/ca', body, env)
      id = JSON.parse(last_response.body)['id']

      # Step 2: Submit a certificate validation request
      body = {
        id: id,
        crt: <<~EOS
        -----BEGIN CERTIFICATE-----
        MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
        A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
        MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
        YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
        ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
        CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
        ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
        dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
        bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
        NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
        +FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
        7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
        4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
        /uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
        rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
        +tZ9KynmrbJpTSi0+BM=
        -----END CERTIFICATE-----
        EOS
      }.to_json
      post('/crypto/validate', body, env)

      # Expect the certificate not to be valid
      valid = JSON.parse(last_response.body)['valid']
      expect(valid).to be_falsy
    end

    it 'returns 500 if an exception is raised' do
      # Force an error on calls to CAService
      allow(CAService).to receive(:instance).and_raise 'Error'

      # Prepare the request
      body = {
        id: SecureRandom.uuid,
        crt: <<~EOS
        -----BEGIN CERTIFICATE-----
        MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
        A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
        MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
        YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
        ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
        CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
        ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
        dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
        bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
        NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
        +FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
        7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
        4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
        /uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
        rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
        +tZ9KynmrbJpTSi0+BM=
        -----END CERTIFICATE-----
        EOS
      }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }

      # Send the request
      post('/crypto/validate', body, env)

      # Expect status code 500
      expect(last_response.status).to eq 500
    end

    it 'returns 400 if the body is not a valid JSON document' do
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/validate', 'Not JSON', env)

      expect(last_response.status).to eq 400
    end

    it 'prevents attempts at path traversal attacks via the ID parameter' do
      body = {
        id: '../../../../../../../../../../../../../../../../../etc/passwd',
        crt: <<~EOS
          -----BEGIN CERTIFICATE-----
          MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
          A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
          MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
          YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
          ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
          CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
          ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
          dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
          bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
          NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
          +FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
          7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
          4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
          /uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
          rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
          +tZ9KynmrbJpTSi0+BM=
          -----END CERTIFICATE-----
        EOS
      }.to_json
      env = {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_API_KEY' => 'TEST_API_KEY'
      }
      post('/crypto/validate', body, env)

      expect(last_response.status).to eq 400
    end
  end
end
