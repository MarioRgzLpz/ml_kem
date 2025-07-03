# frozen_string_literal: true

module MLKEM
  # Core module containing the Public Key Encryption (K-PKE) implementation and the ML-KEM internal logic in two separate classes.
  # 
  # @since 0.1.0
  module Core
    # Implements the Public Key Encryption (K-PKE) as specified in ML-KEM (Kyber).
    # Provides methods for key generation, encryption, and decryption using lattice-based NTT arithmetic.
    #
    # @since 0.1.0
    class KPKE
      # Initializes the KPKE engine with given parameters.
      #
      # @param [Integer] k       Security level (2, 3, or 4 for ML-KEM-512/768/1024)
      # @param [Integer] eta1    Noise parameter for secret and error
      # @param [Integer] eta2    Noise parameter for encryption errors
      # @param [Integer] du      Compression bits for u
      # @param [Integer] dv      Compression bits for v
      # @param [Integer] q       Prime modulus
      def initialize(k, eta1, eta2, du, dv, q = Constants::Q)
        @k = k
        @eta1 = eta1
        @eta2 = eta2
        @du = du
        @dv = dv
        @q = q

        @poly_ops = Math::Polynomial.new(@q)
        @ntt_ops = Math::NTT.new(@q)
        @sampling = Math::Sampling.new(@q)
      end

      # Key generation algorithm (Algorithm 13).
      #
      # @param [String] d Random seed (32 bytes)
      # @return [Array<String>] [public_key, secret_key] both as binary strings
      def keygen(d)
        rho, sig = Crypto::SymmetricPrimitives.g(d + [@k].pack('C'))
        n = 0

        a = Array.new(@k) { Array.new(@k) }
        @k.times do |i|
          @k.times do |j|
            a[i][j] = @sampling.sample_ntt(rho + [j, i].pack('CC'))
          end
        end

        s = Array.new(@k)
        e = Array.new(@k)
        @k.times do |i|
          s[i] = @sampling.sample_poly_cbd(@eta1, Crypto::SymmetricPrimitives.prf(@eta1, sig, n))
          n += 1
          e[i] = @sampling.sample_poly_cbd(@eta1, Crypto::SymmetricPrimitives.prf(@eta1, sig, n))
          n += 1
        end

        s.map! { |v| @ntt_ops.ntt(v) }
        e.map! { |v| @ntt_ops.ntt(v) }

        t = e.dup
        @k.times do |i|
          @k.times do |j|
            t[i] = @poly_ops.add(t[i], @ntt_ops.multiply_ntts(a[i][j], s[j]))
          end
        end

        ek_pke = Math::ByteOperations.byte_encode(12, t, @q) + rho
        dk_pke = Math::ByteOperations.byte_encode(12, s, @q)

        [ek_pke, dk_pke]
      end

      # Encryption algorithm (Algorithm 14).
      #
      # @param [String] ek_pke Public key
      # @param [String] m      Message (32 bytes of encoded bits)
      # @param [String] r      Randomness (32-byte seed)
      # @return [String]       Ciphertext
      def encrypt(ek_pke, m, r)
        n = 0

        t = Array.new(@k)
        @k.times do |i|
          t[i] = Math::ByteOperations.byte_decode(12, ek_pke[(384 * i)...(384 * (i + 1))], @q)
        end
        rho = ek_pke[(384 * @k)...(384 * @k + 32)]

        a = Array.new(@k) { Array.new(@k) }
        @k.times do |i|
          @k.times do |j|
            a[i][j] = @sampling.sample_ntt(rho + [j, i].pack('CC'))
          end
        end

        y = Array.new(@k)
        e1 = Array.new(@k)
        @k.times do |i|
          y[i] = @sampling.sample_poly_cbd(@eta1, Crypto::SymmetricPrimitives.prf(@eta1, r, n))
          n += 1
          e1[i] = @sampling.sample_poly_cbd(@eta2, Crypto::SymmetricPrimitives.prf(@eta2, r, n))
          n += 1
        end
        e2 = @sampling.sample_poly_cbd(@eta2, Crypto::SymmetricPrimitives.prf(@eta2, r, n))

        y.map! { |v| @ntt_ops.ntt(v) }

        u = Array.new(@k) { Array.new(256, 0) }
        @k.times do |i|
          @k.times do |j|
            u[i] = @poly_ops.add(u[i], @ntt_ops.multiply_ntts(a[j][i], y[j]))
          end
        end

        @k.times do |i|
          u[i] = @ntt_ops.inverse_ntt(u[i])
          u[i] = @poly_ops.add(u[i], e1[i])
        end

        mu = @poly_ops.decompress(1, Math::ByteOperations.byte_decode(1, m, @q))

        v = Array.new(256, 0)
        @k.times do |i|
          v = @poly_ops.add(v, @ntt_ops.multiply_ntts(t[i], y[i]))
        end
        v = @ntt_ops.inverse_ntt(v)
        v = @poly_ops.add(v, e2)
        v = @poly_ops.add(v, mu)

        c1 = ''
        @k.times do |i|
          c1 += Math::ByteOperations.byte_encode(@du, @poly_ops.compress(@du, u[i]), @q)
        end
        c2 = Math::ByteOperations.byte_encode(@dv, @poly_ops.compress(@dv, v), @q)

        c1 + c2
      end

      # Decryption algorithm (Algorithm 15).
      #
      # @param [String] dk_pke Secret key
      # @param [String] c      Ciphertext
      # @return [String]       Recovered message (32-byte encoded bitstring)
      def decrypt(dk_pke, c)
        c1 = c[0...(32 * @du * @k)]
        c2 = c[(32 * @du * @k)...(32 * (@du * @k + @dv))]

        up = Array.new(@k)
        @k.times do |i|
          up[i] = @poly_ops.decompress(@du,
                  Math::ByteOperations.byte_decode(@du, c1[(32 * @du * i)...(32 * @du * (i + 1))], @q))
        end

        vp = @poly_ops.decompress(@dv, Math::ByteOperations.byte_decode(@dv, c2, @q))

        s = Array.new(@k)
        @k.times do |i|
          s[i] = Math::ByteOperations.byte_decode(12, dk_pke[(384 * i)...(384 * (i + 1))], @q)
        end

        w = Array.new(256, 0)
        @k.times do |i|
          w = @poly_ops.add(w, @ntt_ops.multiply_ntts(s[i], @ntt_ops.ntt(up[i])))
        end
        w = @poly_ops.subtract(vp, @ntt_ops.inverse_ntt(w))

        Math::ByteOperations.byte_encode(1, @poly_ops.compress(1, w), @q)
      end
    end
  end
end
