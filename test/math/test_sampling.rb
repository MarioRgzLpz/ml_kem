# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Math
    class SamplingTest < Minitest::Test
        def setup
            @q = Constants::Q
            @sampling = Sampling.new(@q)
        end

        def test_sample_ntt
            seed = "\xAA" * 32
            indices = "\x01\x02"
            input = seed + indices
            
            result = @sampling.sample_ntt(input)
            
            assert_equal 256, result.size, "Expected result size to be 256, got #{result.size}"
            result.each do |value|
                assert value < @q, "Value #{value} exceeds modulus #{@q}"
                assert value >= 0, "Value #{value} is negative"
            end
        end

        def test_sample_poly_cbd_eta2
            eta = 2
            input = "\xFF" * (64 * eta)
            
            result = @sampling.sample_poly_cbd(eta, input)
            
            assert_equal 256, result.size, "Expected result size to be 256, got #{result.size}"
            result.each do |value|
                assert value < @q, "Value #{value} exceeds modulus #{@q}"
                assert value >= 0, "Value #{value} is negative"
            end
        end

        def test_sample_poly_cbd_eta3
            eta = 3
            input = "\xAA" * (64 * eta)

            result = @sampling.sample_poly_cbd(eta, input)

            assert_equal 256, result.size, "Expected result size to be 256, got #{result.size}"
            result.each do |value|
                assert value < @q, "Value #{value} exceeds modulus #{@q}"
                assert value >= 0, "Value #{value} is negative"
            end
        end
    end
  end
end
