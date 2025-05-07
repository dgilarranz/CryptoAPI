require 'singleton'

class IOService
  include Singleton

  BASE_PATH = '../cas'

  def initialize
    Dir.mkdir BASE_PATH unless File.directory? BASE_PATH
  end

  def save_ca(id, ca)
    ca_path = "#{BASE_PATH}/#{id}"
    Dir.mkdir ca_path

    # Save the RSA private key
    open "#{ca_path}/key.pem", 'w' do |file|
      file.write ca.key.to_pem
    end

    # Save the root certificate
    open "#{ca_path}/root_crt.pem", 'w' do |file|
      file.write ca.certificate.to_pem
    end

    # Create directory to store emitted certificates
    Dir.mkdir "#{ca_path}/certs"
  end
end
