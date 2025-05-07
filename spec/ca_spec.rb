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

  describe 'when validating a certificate' do
    it 'returns false if it did not emit the certificate' do
      ca = CA.new 'MyCA'
      crt = OpenSSL::X509::Certificate.new <<~EOS
        -----BEGIN CERTIFICATE-----
        MIIGFzCCBP+gAwIBAgIQBXRIzNSoVar0an65vBDlTjANBgkqhkiG9w0BAQsFADBe
        MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
        d3cuZGlnaWNlcnQuY29tMR0wGwYDVQQDExRUaGF3dGUgVExTIFJTQSBDQSBHMTAe
        Fw0yNDEwMTQwMDAwMDBaFw0yNTExMTQyMzU5NTlaMBUxEzARBgNVBAMTCmlrZXJs
        YW4uZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD1jxE9dMngh/dK
        +goC8GPUWQnOe5dlFYDUsGgaK8YvdKh2eFf/RFdF+6isEQ8ncrzlqNCUQdSusMHl
        qqgEmFHBC5Y1nAVQvKubab8OAeeIUo0rw/w5jtC5BHCpXc3IxxiOQJMZ7QPXWe8q
        rjDXldcDu4HJVoaDoyYkyTbisE9LvHT5s3fRZdswA09e5h0/VR/EQpPnFwBvRlE4
        cMLSYJu/Hp4my2TVYFyWdaheFmrD9hNuSaier5G5wiMgDfoO20JB2sG54gR0I2QV
        TnnYnPWEgHcvMDF0FbjCZjpCIOEAC0/DOA2NLTK2jOrtG33QkNZIvnFD0t4dN3Q4
        IumSvDLbAgMBAAGjggMYMIIDFDAfBgNVHSMEGDAWgBSljP4yzOsPLNQZxgi4ACSI
        XcPFtzAdBgNVHQ4EFgQUjv+rczEgVCXwh1fbt0E/qmsGscgwJQYDVR0RBB4wHIIK
        aWtlcmxhbi5lc4IOd3d3LmlrZXJsYW4uZXMwPgYDVR0gBDcwNTAzBgZngQwBAgEw
        KTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1Ud
        DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwOwYDVR0f
        BDQwMjAwoC6gLIYqaHR0cDovL2NkcC50aGF3dGUuY29tL1RoYXd0ZVRMU1JTQUNB
        RzEuY3JsMHAGCCsGAQUFBwEBBGQwYjAkBggrBgEFBQcwAYYYaHR0cDovL3N0YXR1
        cy50aGF3dGUuY29tMDoGCCsGAQUFBzAChi5odHRwOi8vY2FjZXJ0cy50aGF3dGUu
        Y29tL1RoYXd0ZVRMU1JTQUNBRzEuY3J0MAwGA1UdEwEB/wQCMAAwggF9BgorBgEE
        AdZ5AgQCBIIBbQSCAWkBZwB2ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvl
        hiY6AAABkoohBe0AAAQDAEcwRQIhAJbOoerE6LpNSK1pCGpCCHk3WKoxoVicNKtj
        lBUDZFU8AiBfi2glhCH63DU6Y1JhjH+IO5jrwLz3VaXFgSdRjmsyEQB2AMz7D2qF
        cQll/pWbU87psnwi6YVcDZeNtql+VMD+TA2wAAABkoohBiQAAAQDAEcwRQIhALYs
        hWFktLEmjXWKoJC1CbrI+y7Cj4tWIjLH9U7jngyoAiBBvkf9sf76PLeHP4cSjqbO
        hI6aSwJ7SVw3s3uiuytJJQB1AN3cyjSV1+EWBeeVMvrHn/g9HFDf2wA6FBJ2Ciys
        u8gqAAABkoohBiwAAAQDAEYwRAIga8Hx1IeD7hZ4+RPilTdMt8ei65ODRAU4n/hj
        HH59P98CIHAgeJtMoA0zysoc7PMZfMMA7KpbYwaMv81verlqfLtfMA0GCSqGSIb3
        DQEBCwUAA4IBAQDB4wbH3YEYBSlCLes2D2GiFdzVEQ5oEZQVbJlo8nSO6Jn8ofQk
        D2eYjQyaSG7mBDrz4/KUwOdVlo/T0CbPSJaoH9v3NvMQJUwFmUr7X7AD8xiCLFH3
        hJBtFSOoq21eQk/VELesRQn4yNEs3hsxm/sxEDzj/zQdZc2ebdTj1WlUZig7fvF6
        dMIrkyMu5akaZ8KXkUU+nqA0BUQbTWprpQ+o2CsvaYPS5iShS5bIrWODsaZmOmvX
        uVcAfBeekGts+R+CYXS+uOZDJ0Lk/QbxPgWgpSt28hzQ2gvfMoYTzCajp6GJT6f9
        Zy08+xgF2DSnvNPTFi760rC0zqb/X9jowwQQ
        -----END CERTIFICATE-----
      EOS

      expect(ca.validate(crt)).to be_falsy
    end

    it 'returns true if it emitted the certificate' do
      ca = CA.new 'MyCA'
      csr = OpenSSL::X509::Request.new <<~EOS
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
      crt = ca.sign(csr)
      
      expect(ca.validate(crt)).to be_truthy
    end
  end
end
