# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Core
    class KPKETest < Minitest::Test
      def setup
        @k = 3
        @eta1 = 2
        @eta2 = 3
        @du = 10
        @dv = 4
        @q = Constants::Q

        @kpke = KPKE.new(@k, @eta1, @eta2, @du, @dv, @q)

        @d = Array.new(32, 0xAA).pack('C*')
        @r = Array.new(32, 0x55).pack('C*')

        @m = Array.new(32, 0x01).pack('C*')
      end

      def test_kpke_encrypt_decrypt
        ek, dk = @kpke.keygen(@d)

        ciphertext = @kpke.encrypt(ek, @m, @r)
        decrypted = @kpke.decrypt(dk, ciphertext)

        assert_equal @m.unpack1('H*'), decrypted.unpack1('H*'), "Mensaje desencriptado no coincide con el original"
      end
    end
  end
end
