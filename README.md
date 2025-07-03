# MLKEM

**ml_kem** is a Ruby gem that implements the [ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final) post-quantum key encapsulation mechanism (KEM), as selected by NIST for standardization under the FIPS 203. It supports key generation, encapsulation, and decapsulation in pure Ruby and includes a command-line interface for easy integration into workflows.

# Features

- Support for all ML-KEM variants: `ml_kem_512`, `ml_kem_768`, and `ml_kem_1024`
- Public/private key generation
- Secure encapsulation of a shared secret using the public key
- Decapsulation of a ciphertext using the private key
- Command-Line Interface (CLI) built with Thor
- PEM encoding for key files
- Easy to use and integrate into Ruby applications

# Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add ml_kem
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install ml_kem
```

# Usage

## CLI

The `mlkem` command-line tool allows you to generate keys, encapsulate, and decapsulate secrets using ML-KEM.

- **Generate keys:**

    ```bash
    mlkem keygen -p public_key.pem -s private_key.pem -v ml_kem_768
    ```

- **Encapsulate a secret:**

    ```bash
    mlkem encaps -p public_key.pem -c ciphertext.txt -k shared_secret.key
    ```

- **Decapsulate:**

    ```bash
    mlkem decaps -s private_key.pem -c ciphertext.txt -k shared_secret.key
    ```

To obtain information about the options available for a command use:
```bash
mlkem help COMMAND
```

## Code

```bash
require "ml_kem"

# Create an instance with the desired variant

kem = MLKEM::MLKEM.new(variant: :ml_kem_768)

# Generate key pair
public_key, private_key = kem.keygen

# Encapsulate a shared secret
shared_secret, ciphertext = kem.encaps(public_key)

# Decapsulate to recover the shared secret
recovered_secret = kem.decaps(private_key, ciphertext)

```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will start an IRB and allow you to experiment.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/MarioRgzLpz/ml_kem.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
