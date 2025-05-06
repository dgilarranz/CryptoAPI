require 'openssl'

class CA
  attr_reader :private_key

  def initialize(common_name)
    @private_key = OpenSSL::PKey::RSA.new 2048
  end
end
