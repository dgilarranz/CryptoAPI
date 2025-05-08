require_relative '../lib/ca_service'

describe 'The CA Service' do
  before :example do
    # Reset initial state
    loaded_CAs = CAService.instance.instance_variable_get(:@loaded_CAs)
    loaded_CAs.clear

    # Mock IOService.instance before each test to return a double
    @io_service = double('IOService')
    allow(@io_service).to receive(:save_ca)
    allow(@io_service).to receive(:save_certificate)

    allow(IOService).to receive(:instance) { @io_service }
  end

  it 'is a Singleton' do
    expect(CAService).to include Singleton
  end

  describe 'when creating a CA' do
    it 'creates a UUID to identify the CA' do
      id = CAService.instance.create_ca('MyCA')

      expect(id).to match(/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/)
    end

    it 'uses different UUIDs to identify each CA' do
      id1 = CAService.instance.create_ca('MyCA')
      id2 = CAService.instance.create_ca('MyDifferentCA')

      expect(id1).not_to eq id2
    end

    it 'adds the created CA to the list loaded CAs' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca).to be_a CA
    end

    it 'creates a key pair for the CA' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.key).to be_a OpenSSL::PKey::RSA
    end

    it 'creates a 2048 bit RSA key' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      # We check the length of the private key converted to pem. The resulting
      # string should be 1700, 1704 or 1708 characters in length
      # (lengths found empirically using irb and simulating possible values)
      expect([1700, 1704, 1708]).to include ca.key.private_to_pem.length
    end

    it 'creates a root certificate for the CA' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate).to be_a OpenSSL::X509::Certificate
    end

    it 'uses the the requested Common Name (CN) for the CA' do
      common_name = 'MyCA'
      id = CAService.instance.create_ca(common_name)
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.subject.to_s.split('/')[1].split('=').last).to eq common_name
    end

    it 'creates a root certificate with the serial number 0' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expected_serial = OpenSSL::BN.new 0
      expect(ca.certificate.serial).to eq expected_serial
    end

    it 'creates a v3 root certificate (RFC 5280)' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.version).to be 2
    end

    it 'creates a root certificate whose validity starts the moment it is created' do
      # Mock calls to Time.now to return a fixed time
      @time_now = Time.now
      allow(Time).to receive(:now).and_return(@time_now)

      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.not_before.to_i).to eq @time_now.to_i
    end

    it 'creates a root certificate valid for 365 days' do
      # Mock calls to Time.now to return a fixed time
      @time_now = Time.now
      allow(Time).to receive(:now).and_return(@time_now)

      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.not_after.to_i).to eq (@time_now + 365 * 24 * 60 * 60).to_i
    end

    it 'creates a self signed certificate for the CA(issuer = subject)' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.issuer).to eq ca.certificate.subject
    end

    it "creates a root certificate whose public key coincides with the CA's key" do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.public_key.to_s).to eq ca.key.public_key.to_s
    end

    it 'creates a root certificate with a hash based Subject Key Identifier (SKID) extension' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      subject_key_identifier = ca
        .certificate
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/subjectKeyIdentifier/) }
        .first
      expect(subject_key_identifier.match?(/[0-9A-F]{2}(:[0-9A-F]{2}){19}/)).to be_truthy
    end

    it 'creates a root certificate with an extension that allows its usage as a CA' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      basic_constraints = ca
        .certificate
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/basicConstraints/) }
        .first
      expect(basic_constraints.match?(/critical, CA:TRUE/)).to be_truthy
    end

    it "creates a root certificate with an extensions that indicates the CA's key can be used to verify signatures" do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      key_usage= ca
        .certificate
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/keyUsage/) }
        .first
      expect(key_usage.match?(/critical, Certificate Sign, CRL Sign/)).to be_truthy
    end

    it 'creates a self signed root certificate' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(ca.certificate.verify(ca.certificate.public_key)).to be_truthy
    end

    it 'writes the created CA to disk' do
      id = CAService.instance.create_ca('MyCA')
      ca = CAService.instance.instance_variable_get(:@loaded_CAs)[id]

      expect(@io_service).to have_received(:save_ca).with(id, ca)
    end
  end

  describe 'when receiving a petition to sign a certificate' do
    before :example do
      @csr = <<~EOS
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

    it 'returns the PEM string of the signed certificate' do
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')
      ca = ca_service.instance_variable_get(:@loaded_CAs)[id]

      # Sign the certificate request
      signed_crt_pem = ca_service.sign_certificate(id, @csr)

      signed_crt = OpenSSL::X509::Certificate.new(signed_crt_pem)
      expect(ca.validate(signed_crt)).to be_truthy
    end

    it 'saves the signed certificate' do
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')
      ca = ca_service.instance_variable_get(:@loaded_CAs)[id]

      # Sign the certificate request
      signed_crt_pem = ca_service.sign_certificate(id, @csr)

      signed_crt = OpenSSL::X509::Certificate.new(signed_crt_pem)
      expect(@io_service).to have_received(:save_certificate).with(id, signed_crt)
    end

    it 'loads the requested CA if it is not loaded' do
      # Initialise variables
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')
      ca = ca_service.instance_variable_get(:@loaded_CAs)[id]

      # Unload the CA
      ca_service.instance_variable_get(:@loaded_CAs).clear
      allow(@io_service).to receive(:load_ca) { ca }

      # Sign the certificate request
      ca_service.sign_certificate(id, @csr)

      expect(@io_service).to have_received(:load_ca).with(id)
    end
  end

  describe 'when receiving a petition to validate a certificate' do
    it 'returns the true if the CA signed the certificate' do
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')

      # Sign a certificate request
      csr = <<~EOS
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
      crt = ca_service.sign_certificate(id, csr)

      # Validate the certificate
      expect(ca_service.validate_certificate(id, crt)).to be_truthy
    end

    it 'returns false if the CA did not sign the certificate' do
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')

      crt = <<~EOS
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

      expect(ca_service.validate_certificate(id, crt)).to be_falsy
    end

    it 'loads the requested CA if it is not loaded' do
      # Initialise test scenario
      ca_service = CAService.instance
      id = ca_service.create_ca('MyCA')
      ca = ca_service.instance_variable_get(:@loaded_CAs)[id]
      csr = <<~EOS
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
      crt = ca_service.sign_certificate(id, csr)

      # Unload all loadedCAs
      ca_service.instance_variable_get(:@loaded_CAs).clear
      allow(@io_service).to receive(:load_ca) { ca }

      # Request a certificate validation
      ca_service.validate_certificate(id, crt)

      # Expect the CA to have been loaded for the validation
      expect(@io_service).to have_received(:load_ca).with(id)
    end
  end
end
