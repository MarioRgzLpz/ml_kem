# frozen_string_literal: true

require 'sha3'

module MLKEM
  module Math
    # Implements sampling algorithms used in ML-KEM (Kyber),
    # including NTT-domain sampling and centered binomial distribution (CBD).
    #
    # These routines are used to generate polynomial coefficients
    # from uniformly random byte arrays or XOF outputs.
    #
    # @since 0.1.0
    class Sampling
      # Initializes the Sampling object with a modulus `q`.
      #
      # @param [Integer] q The modulus used in coefficient arithmetic.
      #
      # @example
      #   sampling = Sampling.new
      def initialize(q = Constants::Q)
        @q = q
      end

      # Samples a polynomial in the NTT domain from a byte string using SHAKE128.
      #
      # Implements Algorithm 7, SampleNTT(B).
      #
      # This uses rejection sampling to select values uniformly < q from SHAKE128 output.
      #
      # @param [String] b Input byte string to expand into polynomial coefficients.
      # @return [Array<Integer>] A 256-element array of sampled coefficients < q.
      #
      # @example
      #   sampled = sampling.sample_ntt(seed_bytes)
      def sample_ntt(b)
        xof_data = Crypto::HashFunctions.shake128(b, 1024)
        j = 0
        a = []
        i = 0
        
        while j < 256 && i < xof_data.length - 2
          c = xof_data.bytes[i, 3]
          d1 = c[0] + 256 * (c[1] % 16)
          d2 = (c[1] / 16) + 16 * c[2]
          
          if d1 < @q
            a << d1
            j += 1
          end
          
          if d2 < @q && j < 256
            a << d2
            j += 1
          end
          
          i += 3
        end
        
        a
      end

      # Samples a polynomial using centered binomial distribution (CBD).
      #
      # Implements Algorithm 8, SamplePolyCBD_eta(B).
      #
      # The result is a noise polynomial used in ML-KEM.
      #
      # @param [Integer] eta CBD parameter (usually 2 or 3).
      # @param [String] b Byte string used as input entropy.
      # @return [Array<Integer>] A 256-element array of polynomial coefficients modulo q.
      #
      # @example
      #   noise = sampling.sample_poly_cbd(3, seed_bytes)
      def sample_poly_cbd(eta, b)
        b_bits = Math::ByteOperations.bytes_to_bits(b)
        f = Array.new(256, 0)
        
        256.times do |i|
          x = b_bits[(2 * i * eta)...((2 * i + 1) * eta)].sum
          y = b_bits[((2 * i + 1) * eta)...((2 * i + 2) * eta)].sum
          f[i] = (x - y) % @q
        end
        
        f
      end
    end
  end
end
