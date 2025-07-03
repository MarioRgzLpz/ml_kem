# frozen_string_literal: true

module MLKEM
  module Math
    # Implements polynomial arithmetic and compression/decompression
    # operations used in ML-KEM (Kyber) cryptographic schemes.
    #
    # Provides basic modular operations such as addition and subtraction
    # as well as lossy compression methods used to reduce bandwidth.
    #
    # @since 0.1.0
    class Polynomial
      # Initializes a Polynomial instance with a modulus q.
      #
      # @param [Integer] q The modulus used for polynomial arithmetic.
      #
      # @example
      #   poly = Polynomial.new
      def initialize(q = Constants::Q)
        @q = q
      end

      # Adds two polynomials coefficient-wise modulo q.
      #
      # @param [Array<Integer>] f First polynomial.
      # @param [Array<Integer>] g Second polynomial.
      # @return [Array<Integer>] Resulting polynomial (f + g) mod q.
      #
      # @example
      #   result = poly.add([1, 2], [3, 4]) # => [4, 6]
      def add(f, g)
        f.zip(g).map { |a, b| (a + b) % @q }
      end

      # Subtracts one polynomial from another coefficient-wise modulo q.
      #
      # @param [Array<Integer>] f Minuend polynomial.
      # @param [Array<Integer>] g Subtrahend polynomial.
      # @return [Array<Integer>] Resulting polynomial (f - g) mod q.
      #
      # @example
      #   result = poly.subtract([5, 3], [2, 1]) # => [3, 2]
      def subtract(f, g)
        f.zip(g).map { |a, b| (a - b) % @q }
      end

      # Compresses the coefficients of a polynomial to `d` bits.
      #
      # Lossy operation used to reduce size during transmission.
      #
      # @param [Integer] d Number of bits to compress to.
      # @param [Array<Integer>] xv Polynomial coefficients.
      # @return [Array<Integer>] Compressed coefficients.
      #
      # @example
      #   compressed = poly.compress(4, [0, 1000, 2000])
      def compress(d, xv)
        xv.map do |x|
          (((x << d) + (@q - 1) / 2) / @q) % (1 << d)
        end
      end

      # Decompresses `d`-bit values back into approximate polynomial coefficients.
      #
      # Inverse of `#compress`, though lossy.
      #
      # @param [Integer] d Number of bits the coefficients were compressed to.
      # @param [Array<Integer>] yv Compressed coefficients.
      # @return [Array<Integer>] Approximate original coefficients.
      #
      # @example
      #   decompressed = poly.decompress(4, [0, 5, 10])
      def decompress(d, yv)
        yv.map do |y|
          (@q * y + (1 << (d - 1))) >> d
        end
      end
    end
  end
end
