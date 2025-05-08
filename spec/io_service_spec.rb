require 'pp'
require 'fakefs/spec_helpers'
require_relative '../lib/io_service'
require_relative '../lib/ca_service.rb'

describe 'The IO Service' do
  include FakeFS::SpecHelpers

  it 'is a Singleton' do
    expect(IOService).to include Singleton
  end

  it 'uses the correct folder for IO operations' do
    expect(IOService::BASE_PATH).to eq '../cas'
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
    before :example do
      @id = CAService.instance.create_ca('MyCA')
      @ca = CAService.instance.instance_variable_get(:@loaded_CAs)[@id]
    end

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
      @id = CAService.instance.create_ca('MyCA')
      @ca = CAService.instance.instance_variable_get(:@loaded_CAs)[@id]
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
end
