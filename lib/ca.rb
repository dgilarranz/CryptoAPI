require 'openssl'
require 'securerandom'

class CA
  attr_reader :key, :certificate

  def initialize(key, certificate)
    @key = key
    @certificate = certificate
  end

  def sign(csr)
    # Create a new certificate
    crt = OpenSSL::X509::Certificate.new
    crt.serial = SecureRandom.random_number(1 << 160)
    crt.version = 2
    crt.not_before = Time.now
    crt.not_after = crt.not_before + 2 * 365 * 24 * 60 * 60

    # Tailor the certificate to the CSR
    crt.subject = csr.subject
    crt.issuer = @certificate.subject
    crt.public_key = csr.public_key

    # Add extensions
    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = crt
    extension_factory.issuer_certificate = @certificate

    crt.add_extension \
      extension_factory.create_extension('basicConstraints', 'CA:FALSE')
    crt.add_extension \
      extension_factory.create_extension('subjectKeyIdentifier', 'hash')

    # Sign and return the certificate
    crt.sign(@key, OpenSSL::Digest.new('SHA256'))

    crt
  end

  def validate(crt)
    crt.verify @key
  end
end
