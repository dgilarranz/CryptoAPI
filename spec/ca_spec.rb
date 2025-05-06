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
end
