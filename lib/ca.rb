require 'openssl'

class CA
  attr_reader :private_key, :certificate

  def initialize(common_name)
    # Create the key pair
    @private_key = OpenSSL::PKey::RSA.new 2048

    # Create the certificate
    @certificate = OpenSSL::X509::Certificate.new
    @certificate.serial = 0
    @certificate.version = 2
    @certificate.not_before = Time.now
    @certificate.not_after = certificate.not_before + 365 * 24 * 60 * 60

    name = OpenSSL::X509::Name.parse "/CN=#{common_name}"
    @certificate.subject = name
    @certificate.issuer = name
    @certificate.public_key = @private_key.public_key

    # Add extensions
    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = @certificate
    extension_factory.issuer_certificate = @certificate

    @certificate.add_extension \
      extension_factory.create_extension('subjectKeyIdentifier', 'hash')
    @certificate.add_extension \
      extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
    @certificate.add_extension \
      extension_factory.create_extension('keyUsage', 'cRLSign,keyCertSign', true)

    # Self-sign the certificate
    @certificate.sign(@private_key, OpenSSL::Digest.new('SHA256'))
  end

  def sign(csr)
    # Create a new certificate
    crt = OpenSSL::X509::Certificate.new
    crt.serial = 0
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
    crt.sign(@private_key, OpenSSL::Digest.new('SHA256'))

    crt
  end
end
