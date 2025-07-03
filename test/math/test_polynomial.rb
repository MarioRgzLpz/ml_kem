# frozen_string_literal: true

require_relative '../test_helper'

module MLKEM
  module Math
    class PolynomialTest < Minitest::Test
      def setup
        @poly = Polynomial.new
        @q = Constants::Q
      end

      def test_add
        f = [1, 2, 3]
        g = [4, 5, 6]
        expected = [(1 + 4) % @q, (2 + 5) % @q, (3 + 6) % @q]
        assert_equal expected, @poly.add(f, g)
      end

      def test_subtract
        f = [10, 20, 30]
        g = [4, 5, 6]
        expected = [(10 - 4) % @q, (20 - 5) % @q, (30 - 6) % @q]
        assert_equal expected, @poly.subtract(f, g)
      end

      def test_decompress_compress_d_less_than_12
        yv = [0, 1, 1, 0]
        (1..11).each do |d|
          decompressed = @poly.decompress(d, yv)
          compressed = @poly.compress(d, decompressed)
          assert_equal yv, compressed, "Failed for d = #{d}"
        end
      end
    end
  end
end
