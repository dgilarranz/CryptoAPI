# frozen_string_literal: true
module CryptoAPI
  class App < Sinatra::Base
    # Shared behaviour by all endpoints
    before do
      # Response content type is JSON
      content_type :json

      # If the authentication header is missing, return 403
      unless request.env['X-API-Key'] == ENV['API_KEY']
        halt(403, {'Content-Type' => 'text/plain'}, 'Unauthorized')
      end
    end

    # Handle POST requests to /ca
    post '/ca' do
      ENV['API_KEY']
    end
  end
end
