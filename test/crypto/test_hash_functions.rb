# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Crypto
    class HashFunctionsTest < Minitest::Test
      def setup
        @data = "abc"
        @shake128_expected = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        @shake256_expected = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        @sha3_256_expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        @sha3_512_expected = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" \
                             "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
      end

      def test_shake128
        output = HashFunctions.shake128(@data, 32).unpack1('H*')
        assert_equal @shake128_expected, output
      end

      def test_shake256
        output = HashFunctions.shake256(@data, 32).unpack1('H*')
        assert_equal @shake256_expected, output
      end

      def test_sha3_256
        output = HashFunctions.sha3_256(@data).unpack1('H*')
        assert_equal @sha3_256_expected, output
      end

      def test_sha3_512
        output = HashFunctions.sha3_512(@data).unpack1('H*')
        assert_equal @sha3_512_expected, output
      end
    end
  end
end