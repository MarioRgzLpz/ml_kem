# frozen_string_literal: true

require 'thor'
require 'ml_kem'
require 'base64'

module MLKEM
  # Command Line Interface (CLI) for ML-KEM key encapsulation mechanism.
  # Supports key generation, encapsulation, and decapsulation via Thor commands.
  #
  # @example Generate keys
  #   $ mlkem keygen -p pub.pem -s priv.pem
  #
  # @example Encapsulate
  #   $ mlkem encaps -p pub.pem -c ct.txt -k secret.key
  #
  # @example Decapsulate
  #   $ mlkem decaps -s priv.pem -c ct.txt -k secret.key
  #
  # @since 0.1.0
  class CLI < Thor
    # Ensures the CLI exits with a non-zero status code on failure
    def self.exit_on_failure?
      true
    end

    # Global option for selecting the ML-KEM variant
    class_option :variant,
                 aliases: '-v',
                 type: :string,
                 default: 'ml_kem_768',
                 desc: 'Select the ML-KEM variant (ml_kem_512, ml_kem_768, ml_kem_1024)'

    desc "keygen", "Generate a key pair"
    option :pk, aliases: "-p", type: :string, default: "public_key.pem", desc: "Output file for the public key"
    option :sk, aliases: "-s", type: :string, default: "private_key.pem", desc: "Output file for the private key"
    #
    # Generates a public/private key pair and stores them in PEM format.
    #
    # @option options [String] :pk Output path for the public key.
    # @option options [String] :sk Output path for the private key.
    #
    # @example
    #   $ mlkem keygen -p pub.pem -s priv.pem
    def keygen
      mlkem = create_mlkem_instance
      public_key, private_key = mlkem.keygen

      File.write(options[:pk], encode_pem(public_key, "PUBLIC KEY"))
      File.write(options[:sk], encode_pem(private_key, "PRIVATE KEY"))

      puts "Keys generated:\n  Public Key: #{options[:pk]}\n  Private Key: #{options[:sk]}"
    end

    desc "encaps", "Encapsulate a secret using the public key"
    option :pk, aliases: "-p", type: :string, required: true, desc: "Input file containing the public key (for encapsulation)"
    option :sharedkey, aliases: "-k", type: :string, default: "shared_secret.key", desc: "Output file for the shared secret"
    option :ciphertext, aliases: "-c", type: :string, default: "ciphertext.txt", desc: "Output file for the ciphertext"
    #
    # Encapsulates a shared secret using the given public key.
    #
    # @option options [String] :pk Path to PEM-encoded public key file.
    # @option options [String] :sharedkey Output path for the base64-encoded shared secret.
    # @option options [String] :ciphertext Output path for the base64-encoded ciphertext.
    #
    # @example
    #   $ mlkem encaps -p pub.pem -c ct.txt -k secret.key
    def encaps
      mlkem = create_mlkem_instance
      public_key_pem = File.read(options[:pk])
      public_key = decode_pem(public_key_pem)

      secret, ciphertext = mlkem.encaps(public_key)

      File.write(options[:ciphertext], Base64.strict_encode64(ciphertext))
      File.write(options[:sharedkey], Base64.strict_encode64(secret))

      puts "Encapsulation complete:\n  Ciphertext: #{options[:ciphertext]}\n  Shared Secret: #{options[:sharedkey]}"
    end

    desc "decaps", "Decapsulate a ciphertext using the private key"
    option :sk, aliases: "-s", type: :string, required: true, desc: "Input file containing the private key (for decapsulation)"
    option :ciphertext, aliases: "-c", type: :string, required: true, desc: "Ciphertext file to decapsulate"
    option :sharedkey, aliases: "-k", type: :string, default: "shared_secret.key", desc: "Output file for the shared secret"
    #
    # Decapsulates a ciphertext to recover the shared secret using the private key.
    #
    # @option options [String] :sk Path to PEM-encoded private key file.
    # @option options [String] :ciphertext Path to base64-encoded ciphertext file.
    # @option options [String] :sharedkey Output path for the base64-encoded shared secret.
    #
    # @example
    #   $ mlkem decaps -s priv.pem -c ct.txt -k secret.key
    def decaps
      mlkem = create_mlkem_instance
      private_key_pem = File.read(options[:sk])
      private_key = decode_pem(private_key_pem)

      ciphertext_base64 = File.read(options[:ciphertext])
      ciphertext = Base64.decode64(ciphertext_base64)

      secret = mlkem.decaps(private_key, ciphertext)

      File.write(options[:sharedkey], Base64.strict_encode64(secret))

      puts "Decapsulation complete. Shared secret written to #{options[:sharedkey]}"
    end

    private

    # Initializes the ML-KEM instance using the provided variant.
    #
    # @return [MLKEM::MLKEM] Instance for encryption operations.
    # @raise [ArgumentError] if the variant is not recognized.
    def create_mlkem_instance
      variant = options[:variant].to_sym
      valid_variants = [:ml_kem_512, :ml_kem_768, :ml_kem_1024]

      unless valid_variants.include?(variant)
        raise ArgumentError, "Invalid variant: #{options[:variant]}. Valid options are: #{valid_variants.join(', ')}"
      end

      ::MLKEM::MLKEM.new(variant: variant)
    end

    # Decodes a PEM string into binary data.
    #
    # @param [String] pem_str The PEM-encoded key string.
    # @return [String] Raw binary key data.
    def decode_pem(pem_str)
      base64_body = pem_str.lines.reject { |line|
        line =~ /-----BEGIN|-----END/ || line.strip.empty?
      }.join
      Base64.decode64(base64_body)
    end

    # Encodes binary data into PEM format.
    #
    # @param [String] bin_str The binary data.
    # @param [String] label The PEM label (e.g., "PUBLIC KEY").
    # @return [String] PEM-formatted string.
    def encode_pem(bin_str, label)
      encoded = Base64.strict_encode64(bin_str).scan(/.{1,64}/).join("\n")
      "-----BEGIN #{label}-----\n#{encoded}\n-----END #{label}-----\n"
    end
  end
end
