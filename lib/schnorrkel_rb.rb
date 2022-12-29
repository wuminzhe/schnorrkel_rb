# frozen_string_literal: true

require_relative "schnorrkel_rb/version"
require "ffi"

class Str < FFI::AutoPointer
  def self.release(ptr)
    SchnorrkelRb.free(ptr)
  end

  def to_s
    @str ||= read_string.force_encoding("UTF-8")
  end
end

module SchnorrkelRb
  class Error < StandardError; end

  extend FFI::Library
  ffi_lib "#{__dir__}/../target/release/libschnorrkel." + FFI::Platform::LIBSUFFIX
  attach_function :verify, :verify, %i[string string string], :bool
  attach_function :sign_by_seed, :sign_by_seed, %i[string string], Str
  attach_function :free, :free_s, [Str], :void

  def self.sr25519_sign(seed, message)
    message = message[2..] if message.start_with?("0x")
    seed = seed[2..] if seed.start_with?("0x")
    sign_by_seed(message, seed).to_s
  end

  def self.sr25519_verify(signature, message, pubkey)
    pubkey = pubkey[2..] if pubkey.start_with?("0x")
    message = message[2..] if message.start_with?("0x")
    signature = signature[2..] if signature.start_with?("0x")
    verify(signature, message, pubkey)
  end
end
