# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Crypto
    class SymmetricPrimitivesTest < Minitest::Test
      def setup
        @input = "abc"
        @eta = 2
        @n = 7
        @b = SecureRandom.random_bytes(32)
      end

      def test_h
        output = SymmetricPrimitives.h(@input)
        expected = HashFunctions.sha3_256(@input)
        assert_equal 32, output.bytesize
        assert_equal expected.unpack1('H*'), output.unpack1('H*')
      end

      def test_g
        hash = HashFunctions.sha3_512(@input)
        expected0 = hash[0...32]
        expected1 = hash[32...64]

        out0, out1 = SymmetricPrimitives.g(@input)
        assert_equal 32, out0.bytesize
        assert_equal 32, out1.bytesize
        assert_equal expected0.unpack1('H*'), out0.unpack1('H*')
        assert_equal expected1.unpack1('H*'), out1.unpack1('H*')
      end

      def test_j
        output = SymmetricPrimitives.j(@input)
        expected = HashFunctions.shake256(@input, 32)
        assert_equal 32, output.bytesize
        assert_equal expected.unpack1('H*'), output.unpack1('H*')
      end

      def test_prf
        prng_input = @b + [@n].pack('C*')
        expected = HashFunctions.shake256(prng_input, @eta * 64)
        output = SymmetricPrimitives.prf(@eta, @b, @n)
        assert_equal @eta * 64, output.bytesize
        assert_equal expected.unpack1('H*'), output.unpack1('H*')
      end
    end
  end
end
