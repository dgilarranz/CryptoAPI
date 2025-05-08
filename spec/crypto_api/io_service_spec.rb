require_relative '../spec_helper.rb'

describe 'The IO Service' do
  include FakeFS::SpecHelpers

  before :example do
    root_crt = OpenSSL::X509::Certificate.new <<~EOS
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

    key = OpenSSL::PKey::RSA.new <<~EOS
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

    @id = SecureRandom.uuid
    @ca = CA.new(key, root_crt)
  end


  it 'is a Singleton' do
    expect(IOService).to include Singleton
  end

  it 'uses the correct folder for IO operations' do
    expect(IOService::BASE_PATH).to eq './cas'
  end

  describe 'when initialized' do
    it 'creates the base folder if it does not exist' do
      FakeFS do
        _ = IOService.instance

        # The base path should have been created automatically
        expect(Dir.exist?(IOService::BASE_PATH)).to be_truthy
      end
    end
  end

  describe 'when saving a CA' do
    it 'creates a new folder with the supplied identifier' do
      FakeFS do
        # Create base path
        Dir.mkdir IOService::BASE_PATH

        # Save CA
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Check if the folder was created
        expect(File.directory?("#{IOService::BASE_PATH}/#{@id}")).to be_truthy
      end
    end

    it 'saves the private key to a PEM file' do
      FakeFS do
        # Create base path
        Dir.mkdir IOService::BASE_PATH

        # Save CA
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Check if the folder was created
        saved_key = File.read "#{IOService::BASE_PATH}/#{@id}/key.pem"
        expect(saved_key).to eq @ca.key.to_pem
      end
    end

    it 'saves the root certificate to a PEM file' do
      FakeFS do
        # Create base path
        Dir.mkdir IOService::BASE_PATH

        # Save CA
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Check if the folder was created
        saved_crt = File.read "#{IOService::BASE_PATH}/#{@id}/root_crt.pem"
        expect(saved_crt).to eq @ca.certificate.to_pem
      end
    end

    it 'creates a directory to store emitted certificates' do
      FakeFS do
        # Create base path
        Dir.mkdir IOService::BASE_PATH

        # Save CA
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Check if the directory was created
        expect(Dir.exist?("#{IOService::BASE_PATH}/#{@id}/certs")).to be_truthy
      end
    end
  end

  describe 'when saving a certificate' do
    before :example do
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
      @crt = @ca.sign(csr)
    end

    it "saves the buffer into the corresponding CA's folder" do
      FakeFS do
        # Create base path
        Dir.mkdir IOService::BASE_PATH

        # Save CA
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Save the certificate
        io_service.save_certificate(@id, @crt)
        saved_certificate = File.read "#{IOService::BASE_PATH}/#{@id}/#{@crt.serial}.pem"
        expect(saved_certificate).to eq @crt.to_pem
      end
    end
  end

  describe 'when loading a CA' do
    it 'reads the saved RSA private key' do
      FakeFS do
        # Save the CA
        Dir.mkdir IOService::BASE_PATH
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Load the ca
        loaded_ca = io_service.load_ca(@id)
        expect(loaded_ca.key.to_pem).to eq @ca.key.to_pem
      end
    end
    
    it 'reads the saved root certificate' do
      FakeFS do
        # Save the CA
        Dir.mkdir IOService::BASE_PATH
        io_service = IOService.instance
        io_service.save_ca(@id, @ca)

        # Load the ca
        loaded_ca = io_service.load_ca(@id)
        expect(loaded_ca.certificate.to_pem).to eq @ca.certificate.to_pem
      end
    end
  end
end
