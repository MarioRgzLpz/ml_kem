# frozen_string_literal: true
require_relative 'test_helper'

class MLKEMTest < Minitest::Test
  VARIANTS = {
    ml_kem_512: 'ML-KEM-512',
    ml_kem_768: 'ML-KEM-768',
    ml_kem_1024: 'ML-KEM-1024'
  }

  def setup
    @mlkem = MLKEM::MLKEM.new
  end

  def test_initialize_with_default_variant
    assert_instance_of MLKEM::MLKEM, @mlkem
  end

  def test_initialize_with_invalid_variant_raises
    assert_raises(MLKEM::InvalidParameterError) do
      MLKEM::MLKEM.new(variant: :invalid)
    end
  end

  def test_keygen_encaps_decaps_for_all_variants
    VARIANTS.each do |variant_symbol, variant_name|
      mlkem = MLKEM::MLKEM.new(variant: variant_symbol)

      ek, dk = mlkem.keygen
      k_enc, c = mlkem.encaps(ek)
      k_dec = mlkem.decaps(dk, c)

      assert_equal 32, k_enc.bytesize, "Key size should be 32 bytes for #{variant_name}"
      assert_equal 32, k_dec.bytesize, "Recovered key size should be 32 bytes for #{variant_name}"
      assert_equal k_enc, k_dec, "Encapsulated and decapsulated keys should match for #{variant_name}"
    end
  end
end
