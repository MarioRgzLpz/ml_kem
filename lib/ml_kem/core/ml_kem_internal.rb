# frozen_string_literal: true

module MLKEM
  module Core
    # Internal implementation of ML-KEM (Kyber) encapsulation and decapsulation algorithms.
    # Wraps K-PKE logic and adds hashing and key derivation per ML-KEM specification.
    #
    # Algorithms implemented:
    # - Algorithm 16: ML-KEM.KeyGen_internal
    # - Algorithm 17: ML-KEM.Encaps_internal
    # - Algorithm 18: ML-KEM.Decaps_internal
    #
    # @since 0.1.0
    class MLKEMInternal
      # Constructs the internal ML-KEM engine.
      #
      # @param [Integer] k     Security level (1, 3, or 5)
      # @param [Integer] eta1  Noise parameter η₁
      # @param [Integer] eta2  Noise parameter η₂
      # @param [Integer] du    Compression bits for u
      # @param [Integer] dv    Compression bits for v
      def initialize(k, eta1, eta2, du, dv)
        @k = k
        @eta1 = eta1
        @eta2 = eta2
        @du = du
        @dv = dv
        @q = Constants::Q
        @kpke = KPKE.new(@k, @eta1, @eta2, @du, @dv, @q)
      end

      # ML-KEM Key Generation (Algorithm 16).
      #
      # @param [String] d A 32-byte seed for public key derivation.
      # @param [String] z A 32-byte random secret value.
      # @return [Array<String>] [ek, dk] Public and private key pair.
      #
      # @example
      #   ek, dk = kem.keygen_internal(seed, z)
      def keygen_internal(d, z)
        ek_pke, dk_pke = @kpke.keygen(d)
        ek = ek_pke
        dk = dk_pke + ek + Crypto::SymmetricPrimitives.h(ek) + z
        [ek, dk]
      end

      # ML-KEM Encapsulation (Algorithm 17).
      #
      # @param [String] ek Public key.
      # @param [String] m A 32-byte message (uniformly random).
      # @return [Array<String>] [k, c] Shared secret and ciphertext.
      #
      # @example
      #   k, c = kem.encaps_internal(ek, m)
      def encaps_internal(ek, m)
        k, r = Crypto::SymmetricPrimitives.g(m + Crypto::SymmetricPrimitives.h(ek))
        c = @kpke.encrypt(ek, m, r)
        [k, c]
      end

      # ML-KEM Decapsulation (Algorithm 18).
      #
      # @param [String] dk Private key.
      # @param [String] c  Ciphertext.
      # @return [String]   Shared secret (32 bytes).
      #
      # @example
      #   k = kem.decaps_internal(dk, c)
      def decaps_internal(dk, c)
        dk_pke = dk[0...(384 * @k)]
        ek_pke = dk[(384 * @k)...(768 * @k + 32)]
        h_val  = dk[(768 * @k + 32)...(768 * @k + 64)]
        z      = dk[(768 * @k + 64)...(768 * @k + 96)]

        mp = @kpke.decrypt(dk_pke, c)
        kp, rp = Crypto::SymmetricPrimitives.g(mp + h_val)
        kk = Crypto::SymmetricPrimitives.j(z + c)
        cp = @kpke.encrypt(ek_pke, mp, rp)

        c == cp ? kp : kk
      end
    end
  end
end
