# frozen_string_literal: true

require_relative '../test_helper'

class NTTTest < Minitest::Test
  def setup
    @ntt = MLKEM::Math::NTT.new
    @q = MLKEM::Constants::Q
  end

  def test_ntt_and_inverse_ntt
    poly = Array.new(256) { rand(@q) }
    transformed = @ntt.ntt(poly)
    inverted = @ntt.inverse_ntt(transformed)
    assert_equal poly, inverted
  end

  def test_base_case_multiply_properties
    a0, a1 = 3, 5
    b0, b1 = 7, 11
    gamma = 13
    result = @ntt.base_case_multiply(a0, a1, b0, b1, gamma)

    c0_expected = (a0 * b0 + a1 * b1 * gamma) % @q
    c1_expected = (a0 * b1 + a1 * b0) % @q

    assert_equal [c0_expected, c1_expected], result
  end

  def test_multiply_ntts_returns_expected_length
    f = Array.new(256) { rand(@q) }
    g = Array.new(256) { rand(@q) }

    result = @ntt.multiply_ntts(f, g)
    assert_equal 256, result.length
  end
end
