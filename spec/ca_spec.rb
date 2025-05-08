require_relative '../lib/ca'

describe 'A Certificate Authority (CA)' do

  describe 'when created' do
    it 'has a RSA key pair' do
      key = OpenSSL::PKey::RSA.new 2048
      ca = CA.new(key, OpenSSL::X509::Certificate.new)

      expect(ca.key).to be_a OpenSSL::PKey::RSA
    end

    it 'stores the provided a RSA key pair' do
      key = OpenSSL::PKey::RSA.new 2048
      ca = CA.new(key, OpenSSL::X509::Certificate.new)

      expect(ca.key).to be key
    end

    it 'has a root certificate' do
      certificate = OpenSSL::X509::Certificate.new
      ca = CA.new(OpenSSL::PKey::RSA.new, certificate)

      expect(ca.certificate).to be_a OpenSSL::X509::Certificate
    end

    it 'stores the provided a root certificate' do
      certificate = OpenSSL::X509::Certificate.new
      ca = CA.new(OpenSSL::PKey::RSA.new, certificate)

      expect(ca.certificate).to be certificate
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

      @root_crt = OpenSSL::X509::Certificate.new <<~EOS
      -----BEGIN CERTIFICATE-----
      MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
      A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
      MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
      YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
      ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
      CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
      ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
      dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
      bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
      NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
      +FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
      7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
      4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
      /uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
      rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
      +tZ9KynmrbJpTSi0+BM=
      -----END CERTIFICATE-----
      EOS

      @key = OpenSSL::PKey::RSA.new <<~EOS
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEAtM/RXjMp7AvPrnb1/i3ImcZ4ebkY+AvUurTXngJSBgn0GJNM
      1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWmq8rNWtJWJlHlSwiKr8wZDyU0kLAq
      KUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKcHsZp4zz79Jr4+4vF4Bt+/U8luj/l
      lleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7ugZl4aM1uRH7J2oxaexy/JEApSNED
      nO/cripd+Pdqx+m8xbBZ9pX8FsvYnO3D/BKQk3hadbRWg/r8QYT2ZHk0NRyseoUO
      c3hyAeckiSWe2n9lvK+HkxmM23UVtuAwxwj4WQIDAQABAoIBAE76H0d4La2PEy3v
      hE98DA0vJdx1PzTJZigPacb42H8OxfIeFQcOKDlj381OwNO7MliVEe9pHJG3CjH8
      ONhtfBm5wa0UBtFCIFd/6aQUEDYPWECC0kemxV4Sz5yL5vxsVWufKThAW3XnOIrd
      hm74nvzKSeIZ9yvGrU6ipNHY8MUPm0DQVrVYE5MiKjKVExQ4uRAolV2hlmeQDlSt
      k85S0TUOWO1EvJZhsVVs7dBjjY10hIjv3gZPAO8CN85JzMeaNbmWv4RQj0B997in
      rqlOa5qYYt80tAWO4hmPRKCrv6PgThz8C0Cd8AgwNzvQD2d4JpmxxTzBT6/5lRng
      Hhj/wQECgYEA2jxC0a4lGmp1q2aYE1Zyiq0UqjxA92pwFYJg3800MLkf96A+dOhd
      wDAc5aAKN8vQV5g33vKi5+pIHWUCskhTS8/PPGrfeqIvtphCj6b7LKosBOhdzrRD
      Osr+Az/SiR2h5l2lr/v7I8I86RTY7MBk4QcRb601kSagWLDNVzSSdhECgYEA1Bm0
      0sByqkQmFoUNRjwmShPfJeVLTCr1G4clljl6MqHmGyRDHxtcp1+CXlyJJemLQY2A
      qrM7/T4x2ta6ME2WgDydFe9M8oU3BbefNYovS6YnoyBqxCx7yZ1vO0Jo40rZI8Bi
      KoCi6e0Hugg4xyPRz9TTNLmr/yEC1qQesMhM9ckCgYEArsT7rfgMdq8zNOSgfTwJ
      1sztc7d1P67ZvCABfLlVRn+6/hAydGVyTus4+RvFkxGB8+RPOhiOJbQVtJSkKCqL
      qnbtu7DK7+ba1xvwkiJjnE1bm0KLfXIXNQpDik6eSHiWo2nzuo/Ne8GeDftIDbG2
      GBAVAp5v+6I3X0+X4nKTqEECgYEAwT4Cj5mjXxnkEdR7eahHwmpEf0RfzC+/Tate
      RXZsrUDwY34wYWEOk7fjEZIBqrcTl1ATEHNojpxh096bmHK4UnHnNRrn4nYY4W6g
      8ajK2oOxzWA1pjJZPiHgO/+PjLafC4G2br7wr2y0A3yGLnmmKVLgc0NPP42WBnVV
      OP/ljnECgYABlDdJCAehDNSv4mdEzY5bfD+VBFd2QsgE1hYhmUYYRNlgIfIL9Y8e
      CduqXFLNZ/LHdmtYembgUqrMiJTUqcbSrJt26kBQx0az3LAV+J2p68PQ85KR9ZPy
      N1jEnRqpAwEdw7S+8l0yVyaNkm66eRI80p+w3AxNbS9hJ/7UlV3lGA==
      -----END RSA PRIVATE KEY-----
      EOS
    end

    it 'can sign certificate requests' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      expect(crt.verify(ca.key.public_key)).to be_truthy
    end

    it 'emits certificates valid for 2 years' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      expect(crt.not_after).to eq (crt.not_before + 2 * 365 * 24 * 60 * 60)
    end

    it 'emits v3 certificates' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      expect(crt.version).to be 2
    end

    it 'emits certificates for the requested subject' do
      ca = CA.new(@key, @root_crt)

      crt = ca.sign(@csr)
      expect(crt.subject).to eq @csr.subject
    end

    it 'emits certificates with itself as the issuer' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      expect(crt.issuer).to eq ca.certificate.subject
    end

    it 'emits certificates with a hash based Subject Key Identifier (SKID) extension' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      subject_key_identifier = crt
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/subjectKeyIdentifier/) }
        .first

      expect(subject_key_identifier.match?(/[0-9A-F]{2}(:[0-9A-F]{2}){19}/)).to be_truthy
    end

    it 'emits certificates with an extension that disallows their usage as a CA' do
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      basicConstraints = crt
        .extensions
        .map(&:to_s)
        .filter { |ext| ext.match?(/basicConstraints/) }
        .first
      expect(basicConstraints.match?(/CA:FALSE/)).to be_truthy
    end

    it 'should generate different serial numbers for emitted certificates' do
      ca = CA.new(@key, @root_crt)
      crt1 = ca.sign(@csr)
      crt2 = ca.sign(@csr)

      expect(crt2.serial).not_to eq crt1.serial
    end

    it 'should generate random serial numbers' do
      # Mock SecureRandom to verify it is used to create the certificate's serial number
      random_number = SecureRandom.random_number(1 << 160)
      allow(SecureRandom).to receive(:random_number) { random_number }

      # Issue a certificate
      ca = CA.new(@key, @root_crt)
      crt = ca.sign(@csr)

      # Verify the serial number is the result of calling SecureRandom
      expect(crt.serial).to eq random_number
    end

    it 'should generate random serial numbers with 20 bytes of entropy' do
      # Verify SecureRandom uses 20 bytes of entropy
      random_number = SecureRandom.random_number(1 << 160)
      allow(SecureRandom).to receive(:random_number) { random_number }

      # Expect SecureRandom to be called when initialising 
      expect(SecureRandom).to receive(:random_number).with(1<<160).once

      # Issue a certificate
      ca = CA.new(@key, @root_crt)
      ca.sign(@csr)
    end
  end

  describe 'when validating a certificate' do
    before :example do
      @root_crt = OpenSSL::X509::Certificate.new <<~EOS
      -----BEGIN CERTIFICATE-----
      MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
      A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
      MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
      YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
      ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
      CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
      ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
      dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
      bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
      NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
      +FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
      7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
      4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
      /uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
      rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
      +tZ9KynmrbJpTSi0+BM=
      -----END CERTIFICATE-----
      EOS

      @key = OpenSSL::PKey::RSA.new <<~EOS
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEAtM/RXjMp7AvPrnb1/i3ImcZ4ebkY+AvUurTXngJSBgn0GJNM
      1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWmq8rNWtJWJlHlSwiKr8wZDyU0kLAq
      KUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKcHsZp4zz79Jr4+4vF4Bt+/U8luj/l
      lleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7ugZl4aM1uRH7J2oxaexy/JEApSNED
      nO/cripd+Pdqx+m8xbBZ9pX8FsvYnO3D/BKQk3hadbRWg/r8QYT2ZHk0NRyseoUO
      c3hyAeckiSWe2n9lvK+HkxmM23UVtuAwxwj4WQIDAQABAoIBAE76H0d4La2PEy3v
      hE98DA0vJdx1PzTJZigPacb42H8OxfIeFQcOKDlj381OwNO7MliVEe9pHJG3CjH8
      ONhtfBm5wa0UBtFCIFd/6aQUEDYPWECC0kemxV4Sz5yL5vxsVWufKThAW3XnOIrd
      hm74nvzKSeIZ9yvGrU6ipNHY8MUPm0DQVrVYE5MiKjKVExQ4uRAolV2hlmeQDlSt
      k85S0TUOWO1EvJZhsVVs7dBjjY10hIjv3gZPAO8CN85JzMeaNbmWv4RQj0B997in
      rqlOa5qYYt80tAWO4hmPRKCrv6PgThz8C0Cd8AgwNzvQD2d4JpmxxTzBT6/5lRng
      Hhj/wQECgYEA2jxC0a4lGmp1q2aYE1Zyiq0UqjxA92pwFYJg3800MLkf96A+dOhd
      wDAc5aAKN8vQV5g33vKi5+pIHWUCskhTS8/PPGrfeqIvtphCj6b7LKosBOhdzrRD
      Osr+Az/SiR2h5l2lr/v7I8I86RTY7MBk4QcRb601kSagWLDNVzSSdhECgYEA1Bm0
      0sByqkQmFoUNRjwmShPfJeVLTCr1G4clljl6MqHmGyRDHxtcp1+CXlyJJemLQY2A
      qrM7/T4x2ta6ME2WgDydFe9M8oU3BbefNYovS6YnoyBqxCx7yZ1vO0Jo40rZI8Bi
      KoCi6e0Hugg4xyPRz9TTNLmr/yEC1qQesMhM9ckCgYEArsT7rfgMdq8zNOSgfTwJ
      1sztc7d1P67ZvCABfLlVRn+6/hAydGVyTus4+RvFkxGB8+RPOhiOJbQVtJSkKCqL
      qnbtu7DK7+ba1xvwkiJjnE1bm0KLfXIXNQpDik6eSHiWo2nzuo/Ne8GeDftIDbG2
      GBAVAp5v+6I3X0+X4nKTqEECgYEAwT4Cj5mjXxnkEdR7eahHwmpEf0RfzC+/Tate
      RXZsrUDwY34wYWEOk7fjEZIBqrcTl1ATEHNojpxh096bmHK4UnHnNRrn4nYY4W6g
      8ajK2oOxzWA1pjJZPiHgO/+PjLafC4G2br7wr2y0A3yGLnmmKVLgc0NPP42WBnVV
      OP/ljnECgYABlDdJCAehDNSv4mdEzY5bfD+VBFd2QsgE1hYhmUYYRNlgIfIL9Y8e
      CduqXFLNZ/LHdmtYembgUqrMiJTUqcbSrJt26kBQx0az3LAV+J2p68PQ85KR9ZPy
      N1jEnRqpAwEdw7S+8l0yVyaNkm66eRI80p+w3AxNbS9hJ/7UlV3lGA==
      -----END RSA PRIVATE KEY-----
      EOS
    end
    it 'returns false if it did not emit the certificate' do
      ca = CA.new(@key, @root_crt)
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
      ca = CA.new(@key, @root_crt)
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
