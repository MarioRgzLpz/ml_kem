# frozen_string_literal: true

require 'securerandom'
require_relative 'ml_kem/version'
require_relative 'ml_kem/constants'
require_relative 'ml_kem/math/byte_operations'
require_relative 'ml_kem/math/polynomial'
require_relative 'ml_kem/math/ntt'
require_relative 'ml_kem/math/sampling'
require_relative 'ml_kem/crypto/hash_functions'
require_relative 'ml_kem/crypto/symmetric_primitives'
require_relative 'ml_kem/core/k_pke'
require_relative 'ml_kem/core/ml_kem_internal'

module MLKEM
  # Raised when an invalid ML-KEM variant is selected.
  class InvalidParameterError < StandardError; end

  # Raised when cryptographic randomness fails.
  class CryptographicError < StandardError; end

  # Public API class for ML-KEM (Kyber) post-quantum key encapsulation mechanism.
  # Supports key generation, encapsulation, and decapsulation per NIST standard.
  #
  # @author MarioRgzLpz
  # @since 0.1.0
  #
  # @example Basic usage
  #   kem = MLKEM::MLKEM.new(variant: :ml_kem_768)
  #   ek, dk = kem.keygen
  #   k_enc, c = kem.encaps(ek)
  #   k_dec = kem.decaps(dk, c)
  #   raise unless k_enc == k_dec
  class MLKEM
    # Initializes the ML-KEM system with a given variant.
    #
    # @param [Symbol] variant One of `:ml_kem_512`, `:ml_kem_768`, or `:ml_kem_1024`.
    # @raise [InvalidParameterError] if the variant is unsupported.
    def initialize(variant: :ml_kem_768)
      params = Constants::PARAM_SETS[variant.to_s.upcase.gsub('_', '-')]
      raise InvalidParameterError, "Unsupported variant: #{variant}" unless params
      @internal = Core::MLKEMInternal.new(*params)
    end

    # Key generation method (Algorithm 17).
    # Produces a public and private key pair.
    #
    # @return [Array<String>] [ek, dk] Public and private keys (as binary strings).
    # @raise [CryptographicError] if randomness generation fails.
    #
    # @example
    #   ek, dk = kem.keygen
    def keygen
      d = SecureRandom.random_bytes(32)
      z = SecureRandom.random_bytes(32)
      raise CryptographicError, "Random bytes generation failed" if d.nil? || z.nil?

      @internal.keygen_internal(d, z)
    end

    # Encapsulation method (Algorithm 18).
    # Derives a shared secret and ciphertext using the public key.
    #
    # @param [String] ek Public key (as produced by `#keygen`)
    # @return [Array<String>] [k, c] Shared secret and ciphertext
    # @raise [CryptographicError] if randomness generation fails.
    #
    # @example
    #   k, c = kem.encaps(ek)
    def encaps(ek)
      m = SecureRandom.random_bytes(32)
      raise CryptographicError, "Random bytes generation failed" if m.nil?
      @internal.encaps_internal(ek, m)
    end

    # Decapsulation method (Algorithm 19).
    # Recovers the shared secret from the private key and ciphertext.
    #
    # @param [String] dk Private key
    # @param [String] c  Ciphertext (as received from encapsulation)
    # @return [String] Shared secret (32 bytes)
    #
    # @example
    #   k = kem.decaps(dk, c)
    def decaps(dk, c)
      @internal.decaps_internal(dk, c)
    end
  end
end
