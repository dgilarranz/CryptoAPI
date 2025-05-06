require_relative '../lib/ca'

describe 'A Certificate Authority (CA)' do
  it 'has a private key' do
    ca = CA.new 'MyCA'

    expect(ca.private_key).to be_a OpenSSL::PKey::RSA
  end

  it 'has a private key of 2048 bytes' do
    ca = CA.new 'MyCA'

    # We check the length of the private key converted to pem. The resulting
    # string should be 1700, 1704 or 1708 characters in length
    # (lengths found empirically using irb and simulating possible values)
    expect([1700, 1704, 1708]).to include ca.private_key.private_to_pem.length
  end

  it 'has a root certificate' do
    ca = CA.new 'MyCA'

    expect(ca.certificate).to be_a OpenSSL::X509::Certificate
  end

  it 'has a certificate with the requested Common Name (CN)' do
    common_name = 'MyCA'
    ca = CA.new common_name

    expect(ca.certificate.subject.to_s.split('/')[1].split('=').last).to eq common_name
  end

  it 'has a root certificate with the serial number 0' do
    ca = CA.new 'MyCA'

    expected_serial = OpenSSL::BN.new 0
    expect(ca.certificate.serial).to eq expected_serial
  end

  it 'has a v3 root certificate (RFC 5280)' do
    ca = CA.new 'MyCA'

    expect(ca.certificate.version).to be 2
  end

  it 'has a root certificate whose validity starts the moment it is created' do
    # Mock calls to Time.now to return a fixed time
    @time_now = Time.now
    allow(Time).to receive(:now).and_return(@time_now)

    ca = CA.new 'MyCA'

    expect(ca.certificate.not_before.to_i).to eq @time_now.to_i
  end

  it 'has a root certificate valid for 365 days' do
    # Mock calls to Time.now to return a fixed time
    @time_now = Time.now
    allow(Time).to receive(:now).and_return(@time_now)

    ca = CA.new 'MyCA'

    expect(ca.certificate.not_after.to_i).to eq (@time_now + 365 * 24 * 60 * 60).to_i
  end

  it 'has a self signed certificate (issuer = subject)' do
    ca = CA.new 'MyCA'

    expect(ca.certificate.issuer).to eq ca.certificate.subject
  end

  it 'has a certificate whose public key coincides with the created RSA key pair' do
    ca = CA.new 'MyCA'

    expect(ca.certificate.public_key.to_s).to eq ca.private_key.public_key.to_s
  end

  it 'has a certificate with a hash based Subject Key Identifier (SKID) extension' do
    ca = CA.new 'MyCA'

    subject_key_identifier = ca
      .certificate
      .extensions
      .map(&:to_s)
      .filter { |ext| ext.match?(/subjectKeyIdentifier/) }
      .first
    expect(subject_key_identifier.match?(/[0-9A-F]{2}(:[0-9A-F]{2}){19}/)).to be_truthy
  end

  it 'has a certificate with an extension that allows its usage as a CA' do
    ca = CA.new 'MyCA'

    basicConstraints = ca
      .certificate
      .extensions
      .map(&:to_s)
      .filter { |ext| ext.match?(/basicConstraints/) }
      .first
    expect(basicConstraints.match?(/critical, CA:TRUE/)).to be_truthy
  end

  it "has a certificate with an extensions that indicates the CA's key can be used to verify signatures" do
    ca = CA.new 'MyCA'

    basicConstraints = ca
      .certificate
      .extensions
      .map(&:to_s)
      .filter { |ext| ext.match?(/keyUsage/) }
      .first
    expect(basicConstraints.match?(/critical, Certificate Sign, CRL Sign/)).to be_truthy
  end

  it 'has a self signed certificate' do
    ca = CA.new 'MyCA'

    expect(ca.certificate.verify(ca.certificate.public_key)).to be_truthy
  end
end
