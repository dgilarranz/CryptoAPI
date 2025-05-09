# frozen_string_literal: true

module CryptoAPI
  class App < Sinatra::Base
    # Shared behaviour by all endpoints
    before do
      # If the authentication header is missing, return 403
      unless request.env['X-API-Key'] == ENV['API_KEY']
        halt(403, { 'Content-Type': 'text/plain' }, 'Unauthorized')
      end

      # Response content type is JSON
      content_type :json
    end

    post '/ca' do
      # Generate a new CA
      body = JSON.parse request.body.read
      ca_service = CAService.instance
      id = ca_service.create_ca(body['common_name'])
      crt = ca_service.loaded_CAs[id].certificate.to_pem

      # Return ID and PEM Certificate
      { id: id, crt: crt }.to_json
    rescue JSON::ParserError
      halt 400
    rescue
      halt 500
    end

    post '/csr' do
      # Attempt to sign the certificate
      body = JSON.parse request.body.read
      ca_service = CAService.instance
      crt = ca_service.sign_certificate(body['id'], body['csr'])

      # Return ID and PEM Certificate
      { crt: crt }.to_json
    rescue JSON::ParserError
      halt 400
    rescue
      halt 500
    end
  end
end
