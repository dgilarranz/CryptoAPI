# frozen_string_literal: true

module CryptoAPI
  class App < Sinatra::Base
    # Shared behaviour by all endpoints
    before do
      # If the authentication header is missing, return 403
      unless request.env['HTTP_X_API_KEY'] == ENV['API_KEY']
        halt(403, { 'Content-Type': 'text/plain' }, 'Unauthorized')
      end

      # Response content type is JSON
      content_type :json
    end

    post '/crypto/ca' do
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

    post '/crypto/csr' do
      # Validate sensitive input to prevent attacks
      body = JSON.parse request.body.read
      halt 400 unless valid_id?(body['id'])

      # Attempt to sign the certificate
      ca_service = CAService.instance
      crt = ca_service.sign_certificate(body['id'], body['csr'])

      # Return ID and PEM Certificate
      { crt: crt }.to_json
    rescue JSON::ParserError
      halt 400
    rescue
      halt 500
    end

    post '/crypto/validate' do
      # Validate sensitive input to prevent attacks
      body = JSON.parse request.body.read
      halt 400 unless valid_id?(body['id'])

      # Validate the certificate
      ca_service = CAService.instance
      valid = ca_service.validate_certificate(body['id'], body['crt'])

      # Return the result
      { valid: valid }.to_json
    rescue JSON::ParserError
      halt 400
    rescue
      halt 500
    end

    def valid_id?(id)
      id.match?(/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/)
    end
  end
end
