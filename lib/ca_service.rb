require 'securerandom'
require 'singleton'
require_relative './ca'

class CAService
  include Singleton

  def initialize
    @loaded_CAs = {}
  end

  def create_ca(common_name)
    # Create an id for the new CA
    id = SecureRandom.uuid

    # Create the key pair
    key = OpenSSL::PKey::RSA.new 2048

    # Create and self-sign the certificate
    certificate = create_certificate(common_name, key.public_key)
    add_extensions(certificate)
    certificate.sign(key, OpenSSL::Digest.new('SHA256'))

    # Create a new CA and save it to disk
    ca = CA.new(key, certificate)
    # TODO: save CA
    @loaded_CAs[id] = ca

    id
  end

  private

  def create_certificate(common_name, public_key)
    certificate = OpenSSL::X509::Certificate.new
    certificate.serial = 0
    certificate.version = 2
    certificate.not_before = Time.now
    certificate.not_after = certificate.not_before + 365 * 24 * 60 * 60

    name = OpenSSL::X509::Name.parse "/CN=#{common_name}"
    certificate.subject = name
    certificate.issuer = name
    certificate.public_key = public_key

    certificate
  end

  def add_extensions(certificate)
    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = certificate
    extension_factory.issuer_certificate = certificate

    certificate.add_extension \
      extension_factory.create_extension('subjectKeyIdentifier', 'hash')
    certificate.add_extension \
      extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
    certificate.add_extension \
      extension_factory.create_extension('keyUsage', 'cRLSign,keyCertSign', true)
  end
end
