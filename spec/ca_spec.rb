require_relative '../lib/ca'

describe 'A Certificate Authority (CA)' do

  describe 'when created' do
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

      basic_constraints = ca
        .certificate
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/basicConstraints/) }
        .first
      expect(basic_constraints.match?(/critical, CA:TRUE/)).to be_truthy
    end

    it "has a certificate with an extensions that indicates the CA's key can be used to verify signatures" do
      ca = CA.new 'MyCA'

      key_usage= ca
        .certificate
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/keyUsage/) }
        .first
      expect(key_usage.match?(/critical, Certificate Sign, CRL Sign/)).to be_truthy
    end

    it 'has a self signed certificate' do
      ca = CA.new 'MyCA'

      expect(ca.certificate.verify(ca.certificate.public_key)).to be_truthy
    end
  end

  describe 'when signing a CSR' do
    before :example do
      @csr = OpenSSL::X509::Request.new <<~EOS
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
    end

    it 'can sign certificate requests' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      expect(crt.verify(ca.private_key.public_key)).to be_truthy
    end

    it 'emits certificates valid for 2 years' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      expect(crt.not_after).to eq (crt.not_before + 2 * 365 * 24 * 60 * 60)
    end

    it 'emits v3 certificates' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      expect(crt.version).to be 2
    end

    it 'emits certificates for the requested subject' do
      ca = CA.new 'MyCA'

      crt = ca.sign(@csr)
      expect(crt.subject).to eq @csr.subject
    end

    it 'emits certificates with itself as the issuer' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      expect(crt.issuer).to eq ca.certificate.subject
    end

    it 'emits certificates with a hash based Subject Key Identifier (SKID) extension' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      subject_key_identifier = crt
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/subjectKeyIdentifier/) }
        .first

      expect(subject_key_identifier.match?(/[0-9A-F]{2}(:[0-9A-F]{2}){19}/)).to be_truthy
    end

    it 'emits certificates with an extension that disallows their usage as a CA' do
      ca = CA.new 'MyCA'
      crt = ca.sign(@csr)

      basicConstraints = crt
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/basicConstraints/) }
        .first
      expect(basicConstraints.match?(/CA:FALSE/)).to be_truthy
    end
  end
end
