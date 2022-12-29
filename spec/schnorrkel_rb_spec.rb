# frozen_string_literal: true

RSpec.describe SchnorrkelRb do
  it "can verify correctly" do
    sig = "4e9d84c9d67241f916272c3f39cd145d847cfeed322b3a4fcba67e1113f8b21440396cb7624113c14af2cd76850fc8445ec538005d7d39ce664e5fb0d926a48f"
    msg = "68656c6c6f2c20776f726c64" # "test message"
    pk = "d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746"
    result = SchnorrkelRb.sr25519_verify(sig, msg, pk)
    expect(result).to eq(true)
  end

  it "can sign correctly" do
    seed = "c8fa03532fb22ee1f7f6908b9c02b4e72483f0dbd66e4cd456b8f34c6230b849"
    msg = "68656c6c6f2c20776f726c64" # "test message"
    sig = SchnorrkelRb.sr25519_sign(seed, msg)

    pk = "d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746"
    result = SchnorrkelRb.sr25519_verify(sig, msg, pk)
    expect(result).to eq(true)
  end
end
