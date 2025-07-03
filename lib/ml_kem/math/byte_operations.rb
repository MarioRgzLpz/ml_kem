# frozen_string_literal: true

module MLKEM
  # Math module containing all the math related operations to NTT, byte operations, polynomial and sampling.
  #
  # @since 0.1.0
  module Math
    # Byte and bit manipulation operations used in the ML-KEM standard (2024).
    #
    # Provides methods to convert between bit arrays and byte strings,
    # and to encode and decode arrays according to given parameters.
    #
    # @since 0.1.0
    class ByteOperations
      # Converts an array of bits into a byte string.
      #
      # Implements Algorithm 3, BitsToBytes(b).
      #
      # @param [Array<Integer>] b An array of bits (0 or 1).
      # @return [String] The resulting byte string.
      #
      # @example
      #   bits = [1,0,1,0,1,0,1,0]
      #   ByteOperations.bits_to_bytes(bits) # => "\x55" (byte representation)
      def self.bits_to_bytes(b)
        l = b.length
        a = Array.new(l / 8, 0)
        (0...l).step(8) do |i|
          x = 0
          8.times do |j|
            x += b[i + j] << j
          end
          a[i / 8] = x
        end
        a.pack('C*')
      end

      # Converts a byte string into an array of bits.
      #
      # Implements Algorithm 4, BytesToBits(B).
      #
      # @param [String] b A byte string.
      # @return [Array<Integer>] The resulting array of bits (0 or 1).
      #
      # @example
      #   bytes = "\x55"
      #   ByteOperations.bytes_to_bits(bytes) # => [1,0,1,0,1,0,1,0]
      def self.bytes_to_bits(b)
        l = b.length
        a = Array.new(8 * l, 0)
        (0...(8 * l)).step(8) do |i|
          x = b.bytes[i / 8]
          8.times do |j|
            a[i + j] = (x >> j) & 1
          end
        end
        a
      end

      # Encodes an array of values into a byte string using dimension d and modulus q.
      #
      # Implements Algorithm 5, ByteEncode_d(F).
      #
      # @param [Integer] d Number of bits per value.
      # @param [Array<Integer>, Array<Array<Integer>>] f Array of values or array of arrays to encode.
      # @param [Integer] q Modulus for values (kept for compatibility; unused internally).
      # @return [String] The encoded byte string.
      #
      # @example
      #   d = 8
      #   f = Array.new(256) { |i| i }
      #   ByteOperations.byte_encode(d, f, 256) # => encoded string
      #
      # @example Encoding multiple arrays:
      #   f_multi = [Array.new(256, 1), Array.new(256, 2)]
      #   ByteOperations.byte_encode(d, f_multi, 256) # => concatenated encoded string
      def self.byte_encode(d, f, q)
        if f.first.is_a?(Array)
          return f.map { |x| byte_encode(d, x, q) }.join
        end

        b = Array.new(256 * d, 0)

        256.times do |i|
          a = f[i]
          d.times do |j|
            b[d * i + j] = (a >> j) & 1
          end
        end
        bits_to_bytes(b)
      end

      # Decodes a byte string into an array of values using dimension d and modulus q.
      #
      # Implements Algorithm 6, ByteDecode_d(B).
      #
      # @param [Integer] d Number of bits per value.
      # @param [String] b Encoded byte string.
      # @param [Integer] q Modulus for values.
      # @return [Array<Integer>] The decoded array of values.
      #
      # @example
      #   d = 8
      #   encoded = ByteOperations.byte_encode(d, Array.new(256, 42), 256)
      #   ByteOperations.byte_decode(d, encoded, 256) # => Array with value 42 repeated
      def self.byte_decode(d, b, q)
        bits_array = bytes_to_bits(b)
        f = Array.new(256, 0)

        256.times do |i|
          a = 0
          d.times do |j|
            a += bits_array[d * i + j] << j
          end
          f[i] = a % q
        end
        f
      end
    end
  end
end
