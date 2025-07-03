# frozen_string_literal: true

require_relative '../test_helper'

class ByteOperationsTest < Minitest::Test
    def setup
        @q = MLKEM::Constants::Q
    end

    def test_bits_to_bytes
        bits = [0, 1, 0, 1, 0, 1, 0, 1]
        expected_bytes = "\xAA".dup.force_encoding('ASCII-8BIT')
        assert_equal expected_bytes, MLKEM::Math::ByteOperations.bits_to_bytes(bits)

        bits_multiple_bytes = [1, 0, 0, 0, 0, 0, 0, 0,
                                0, 1, 0, 0, 0, 0, 0, 0] 
        expected_bytes_multiple = "\x01\x02".dup.force_encoding('ASCII-8BIT')
        assert_equal expected_bytes_multiple, MLKEM::Math::ByteOperations.bits_to_bytes(bits_multiple_bytes)
    end

    def test_bytes_to_bits
        bytes = "\xAA".dup.force_encoding('ASCII-8BIT')
        expected_bits = [0, 1, 0, 1, 0, 1, 0, 1]
        assert_equal expected_bits, MLKEM::Math::ByteOperations.bytes_to_bits(bytes)

        bytes_multiple_bytes = "\x01\x02".dup.force_encoding('ASCII-8BIT')
        expected_bits_multiple = [1, 0, 0, 0, 0, 0, 0, 0,
                                    0, 1, 0, 0, 0, 0, 0, 0] 
        assert_equal expected_bits_multiple, MLKEM::Math::ByteOperations.bytes_to_bits(bytes_multiple_bytes)
    end

    def test_byte_encode_decode_d1
        d = 1 
        f = Array.new(256) { |i| i % 2 }

        encoded_bytes = MLKEM::Math::ByteOperations.byte_encode(d, f, @q)
        decoded_f = MLKEM::Math::ByteOperations.byte_decode(d, encoded_bytes, @q)

        assert_equal f, decoded_f
    end

    def test_byte_encode_decode_d12
        d = 12
        f = Array.new(256) { |i| i * 13 % (1 << d) }

        encoded_bytes = MLKEM::Math::ByteOperations.byte_encode(d, f, @q)
        decoded_f = MLKEM::Math::ByteOperations.byte_decode(d, encoded_bytes, @q)

        assert_equal f, decoded_f
    end

    def test_byte_encode_with_multiple_polynomials
        d = 12
        f_multi = [
            Array.new(256) { |i| i * 5 % @q },
            Array.new(256) { |i| (i * 5 + 1) % @q }
        ]

        encoded_bytes = MLKEM::Math::ByteOperations.byte_encode(d, f_multi, @q)

        expected_length_per_poly = (256 * d / 8)
        assert_equal expected_length_per_poly * f_multi.length, encoded_bytes.length

        decoded_f1 = MLKEM::Math::ByteOperations.byte_decode(d, encoded_bytes[0...expected_length_per_poly], @q)
        decoded_f2 = MLKEM::Math::ByteOperations.byte_decode(d, encoded_bytes[expected_length_per_poly...(expected_length_per_poly * 2)], @q)

        assert_equal f_multi[0], decoded_f1
        assert_equal f_multi[1], decoded_f2
    end
end