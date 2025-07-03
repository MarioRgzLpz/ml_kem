# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Core
    class MLKEMInternalTest < Minitest::Test
      def setup
        @k = 2
        @eta1 = 2
        @eta2 = 3
        @du = 10
        @dv = 4

        @kem = MLKEMInternal.new(@k, @eta1, @eta2, @du, @dv)
      end

      def test_keygen_encaps_decaps
        d = SecureRandom.random_bytes(32)
        z = SecureRandom.random_bytes(32)

        ek, dk = @kem.keygen_internal(d, z)

        m = SecureRandom.random_bytes(32)
        k_enc, c = @kem.encaps_internal(ek, m)
        k_dec = @kem.decaps_internal(dk, c)

        assert_equal k_enc, k_dec, "Key mismatch after encapsulation and decapsulation"
      end
    end
  end
end