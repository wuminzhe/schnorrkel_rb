# frozen_string_literal: true

require_relative "schnorrkel_rb/version"
require "ffi"

class Str < FFI::AutoPointer
  def self.release(ptr)
    SchnorrkelRb.free(ptr)
  end

  def to_s
    @str ||= self.read_string.force_encoding('UTF-8')
  end
end

def to_bytes(str)
  data = str.start_with?('0x') ? str[2..] : str
  raise 'Not valid hex string' if data =~ /[^\da-f]+/i

  data = "0#{data}" if data.length.odd?
  data.scan(/../).map(&:hex)
end

module SchnorrkelRb
  class Error < StandardError; end

  extend FFI::Library
  ffi_lib "#{__dir__}/../target/release/libschnorrkel." + FFI::Platform::LIBSUFFIX
  attach_function :sign, %i[pointer int pointer int], Str
  attach_function :free, :my_free, [Str], :void

  def self.sr25519_sign(message, seed)
    message_data = to_bytes(message)
    m = FFI::MemoryPointer.new(:int8, message_data.size)
    m.write_array_of_int8 message_data

    seed_data = to_bytes(seed)
    s = FFI::MemoryPointer.new(:int8, seed_data.size)
    s.write_array_of_int8 seed_data

    self.sign(m, m.size, s, s.size).to_s
  end
end
