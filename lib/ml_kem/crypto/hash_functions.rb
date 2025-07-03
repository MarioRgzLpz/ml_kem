# frozen_string_literal: true

require 'sha3'

module MLKEM
  # Module containing an adjusted version of the Kyber hash functions
  # used for cryptographic operations in ML-KEM.
  #
  # @since 0.1.0 
  module Crypto
    # Provides cryptographic hash functions used in ML-KEM (Kyber),
    # including SHAKE128, SHAKE256, SHA3-256, and SHA3-512.
    #
    #
    # @since 0.1.0
    class HashFunctions
      class << self
        # Computes the SHAKE128 extendable-output function (XOF).
        #
        # @param [String] data Input byte string.
        # @param [Integer] length Number of output bytes to produce.
        # @return [String] XOF output of the specified length.
        #
        # @example
        #   out = HashFunctions.shake128("seed", 32)
        def shake128(data, length)
          shake = SHA3::Digest::SHAKE_128.new
          shake << data
          shake.squeeze(length)
        end

        # Computes the SHAKE256 extendable-output function (XOF).
        #
        # @param [String] data Input byte string.
        # @param [Integer] length Number of output bytes to produce.
        # @return [String] XOF output of the specified length.
        #
        # @example
        #   out = HashFunctions.shake256("key", 64)
        def shake256(data, length)
          shake = SHA3::Digest::SHAKE_256.new
          shake << data
          shake.squeeze(length)
        end

        # Computes the SHA3-256 hash of the given data.
        #
        # @param [String] data Input byte string.
        # @return [String] 32-byte hash digest.
        #
        # @example
        #   digest = HashFunctions.sha3_256("message")
        def sha3_256(data)
          digest = SHA3::Digest.new(:sha3_256)
          digest.update(data)
          digest.digest
        end

        # Computes the SHA3-512 hash of the given data.
        #
        # @param [String] data Input byte string.
        # @return [String] 64-byte hash digest.
        #
        # @example
        #   digest = HashFunctions.sha3_512("message")
        def sha3_512(data)
          digest = SHA3::Digest.new(:sha3_512)
          digest.update(data)
          digest.digest
        end
      end
    end
  end
end
