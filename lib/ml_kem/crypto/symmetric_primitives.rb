# frozen_string_literal: true

require 'sha3'

module MLKEM
  module Crypto
    # Provides symmetric cryptographic primitives as defined by ML-KEM (Kyber),
    # including hash functions h, g, j and a pseudorandom function (PRF).
    #
    # These are used for key derivation, random generation, and message hashing.
    #
    # @since 0.1.0
    class SymmetricPrimitives
      class << self
        # Hash function h: SHA3-256
        #
        # @param [String] x Input data to hash.
        # @return [String] 32-byte digest.
        #
        # @example
        #   digest = SymmetricPrimitives.h("message")
        def h(x)
          HashFunctions.sha3_256(x)
        end

        # Hash function g: SHA3-512, split into two 32-byte outputs.
        #
        # @param [String] x Input data to hash.
        # @return [Array<String>] An array containing two 32-byte strings.
        #
        # @example
        #   g1, g2 = SymmetricPrimitives.g("seed")
        def g(x)
          hash = HashFunctions.sha3_512(x)
          [hash[0...32], hash[32...64]]
        end

        # Hash function j: SHAKE256 with 32-byte output.
        #
        # @param [String] s Input data to hash.
        # @return [String] 32-byte XOF output.
        #
        # @example
        #   result = SymmetricPrimitives.j("domain")
        def j(s)
          HashFunctions.shake256(s, 32)
        end

        # Pseudorandom Function (PRF)
        #
        # Uses SHAKE256 to expand `s || b` into `eta * 64` bytes of pseudorandom data.
        #
        # @param [Integer] eta Security parameter (e.g., 2 or 3).
        # @param [String] s Secret seed.
        # @param [Integer] b A single byte to include in domain separation.
        # @return [String] Pseudorandom byte string of length `eta * 64`.
        #
        # @example
        #   prf_output = SymmetricPrimitives.prf(3, "key", 0x01)
        def prf(eta, s, b)
          input = s + [b].pack('C*')
          HashFunctions.shake256(input, eta * 64)
        end
      end
    end
  end
end
