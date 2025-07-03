# frozen_string_literal: true

module MLKEM
  module Math
    # Implements the Number Theoretic Transform (NTT) and related operations
    # as defined in the ML-KEM standard (2024), used for polynomial arithmetic
    # in the ring Z_q[X]/(X^256 + 1).
    #
    # Includes forward and inverse NTT transforms, pointwise multiplication,
    # and the base case multiplication algorithm.
    #
    # @since 0.1.0
    class NTT
      # Initializes an NTT instance with a modulus `q`.
      #
      # @param [Integer] q The modulus for all modular arithmetic.
      #
      # @example
      #   ntt = NTT.new
      def initialize(q = Constants::Q)
        @q = q
      end

      # Applies the forward Number Theoretic Transform to a polynomial.
      #
      # Implements Algorithm 9, NTT(f).
      #
      # @param [Array<Integer>] f A 256-element array representing the polynomial.
      # @return [Array<Integer>] The transformed polynomial.
      #
      # @example
      #   transformed = ntt.ntt(original_poly)
      def ntt(f)
        f = f.dup
        i = 1
        le = 128
        
        while le >= 2
          (0...256).step(2 * le) do |st|
            ze = Constants::ZETA_NTT[i]
            i += 1
            (st...(st + le)).each do |j|
              t = (ze * f[j + le]) % @q
              f[j + le] = (f[j] - t) % @q
              f[j] = (f[j] + t) % @q
            end
          end
          le /= 2
        end
        
        f
      end

      # Applies the inverse Number Theoretic Transform to a polynomial.
      #
      # Implements Algorithm 10, NTT^<sup>-1</sup>(f).
      #
      # @param [Array<Integer>] f A 256-element array in the NTT domain.
      # @return [Array<Integer>] The inverse-transformed polynomial.
      #
      # @example
      #   original = ntt.inverse_ntt(transformed_poly)
      def inverse_ntt(f)
        f = f.dup
        i = 127
        le = 2
        
        while le <= 128
          (0...256).step(2 * le) do |st|
            ze = Constants::ZETA_NTT[i]
            i -= 1
            (st...(st + le)).each do |j|
              t = f[j]
              f[j] = (t + f[j + le]) % @q
              f[j + le] = (ze * (f[j + le] - t)) % @q
            end
          end
          le *= 2
        end
        
        f.map { |x| (x * 3303) % @q }
      end

      # Performs pointwise multiplication in the NTT domain.
      #
      # Implements Algorithm 11, MultiplyNTTs(~f, ~g).
      #
      # @param [Array<Integer>] f First polynomial in NTT form.
      # @param [Array<Integer>] g Second polynomial in NTT form.
      # @return [Array<Integer>] Result of the pointwise multiplication.
      #
      # @example
      #   product = ntt.multiply_ntts(ntt_f, ntt_g)
      def multiply_ntts(f, g)
        h = []
        (0...256).step(2) do |ii|
          h.concat(base_case_multiply(f[ii], f[ii + 1], g[ii], g[ii + 1], 
                                      Constants::ZETA_MUL[ii / 2]))
        end
        h
      end

      # Performs the base case multiplication for two polynomial coefficient pairs.
      #
      # Implements Algorithm 12, BaseCaseMultiply(a0, a1, b0, b1, gamma).
      #
      # @param [Integer] a0 Coefficient a_0
      # @param [Integer] a1 Coefficient a_1
      # @param [Integer] b0 Coefficient b_0
      # @param [Integer] b1 Coefficient b_1
      # @param [Integer] gam Precomputed gamma value
      # @return [Array<Integer>] The resulting coefficients [c0, c1]
      #
      # @example
      #   ntt.base_case_multiply(3, 4, 5, 6, gamma) # => [expected_c0, expected_c1]
      def base_case_multiply(a0, a1, b0, b1, gam)
        c0 = (a0 * b0 + a1 * b1 * gam) % @q
        c1 = (a0 * b1 + a1 * b0) % @q
        [c0, c1]
      end
    end
  end
end
