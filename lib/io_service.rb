# frozen_string_literal: true

require 'singleton'

class IOService
  include Singleton

  BASE_PATH = './cas'
  RSA_KEY_FILENAME = 'key.pem'
  ROOT_CRT_FILENAME = 'root_crt.pem'
  CA_CERTS_DIRECTORY = 'certs'

  def initialize
    Dir.mkdir BASE_PATH unless File.directory? BASE_PATH
  end

  def save_ca(id, ca)
    ca_path = "#{BASE_PATH}/#{id}"
    Dir.mkdir ca_path

    # Save the RSA private key
    File.open "#{ca_path}/#{RSA_KEY_FILENAME}", 'w' do |file|
      file.write ca.key.to_pem
    end

    # Save the root certificate
    File.open "#{ca_path}/#{ROOT_CRT_FILENAME}", 'w' do |file|
      file.write ca.certificate.to_pem
    end

    # Create directory to store emitted certificates
    Dir.mkdir "#{ca_path}/#{CA_CERTS_DIRECTORY}"
  end

  def save_certificate(ca_id, certificate)
    File.open "#{BASE_PATH}/#{ca_id}/#{certificate.serial}.pem", 'w' do |file|
      file.write certificate.to_pem
    end
  end

  def load_ca(ca_id)
    # Load the RSA private key
    pem_key = File.read "#{BASE_PATH}/#{ca_id}/#{RSA_KEY_FILENAME}"
    key = OpenSSL::PKey::RSA.new(pem_key)

    # Load the root certificate
    pem_crt = File.read "#{BASE_PATH}/#{ca_id}/#{ROOT_CRT_FILENAME}"
    root_crt = OpenSSL::X509::Certificate.new(pem_crt)

    CA.new(key, root_crt)
  end
end
