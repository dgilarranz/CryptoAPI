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
end
