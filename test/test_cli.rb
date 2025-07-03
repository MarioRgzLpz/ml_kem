# frozen_string_literal: true
require_relative 'test_helper'
require 'ml_kem/cli' 
require 'stringio'

class MLKEMCLITest < Minitest::Test
  def setup
    @cli = MLKEM::CLI.new
    ['public_key.pem', 'private_key.pem', 'ciphertext.txt', 'shared_secret.key'].each do |file|
      File.delete(file) if File.exist?(file)
    end
  end

  def test_keygen_command_creates_key_files
    out, _ = capture_io do
      @cli.invoke(:keygen)
    end

    assert File.exist?('public_key.pem'), "Expected public_key.pem to be created"
    assert File.exist?('private_key.pem'), "Expected private_key.pem to be created"
    assert_match /Keys generated/, out
  end

  def test_encaps_and_decaps_flow
    out, _ = capture_io do
      @cli.invoke(:keygen)
    end
    public_key = File.read('public_key.pem')
    private_key = File.read('private_key.pem')

    File.write('temp_public_key.pem', public_key)

    out_encaps, _ = capture_io do
      @cli.invoke(:encaps, [], pk: 'temp_public_key.pem')
    end

    assert File.exist?('ciphertext.txt'), "Expected ciphertext output file"
    assert File.exist?('shared_secret.key'), "Expected shared_secret.key from encaps"
    assert_match /Encapsulation complete/, out_encaps

    out_decaps, _ = capture_io do
      @cli.invoke(:decaps, [], sk: 'private_key.pem', ciphertext: 'ciphertext.txt')
    end

    assert File.exist?('shared_secret.key'), "Expected shared secret output from decaps"
    assert_match /Decapsulation complete/, out_decaps
  ensure
    ['temp_public_key.pem', 'test_ciphertext.txt', 'test_shared_secret.key', 'shared_secret.key', 'public_key.pem', 'private_key.pem'].each do |file|
      File.delete(file) if File.exist?(file)
    end
  end

  def test_invalid_variant_raises_error
    e = assert_raises(ArgumentError) do
      @cli.invoke(:keygen, [], variant: 'invalid_variant')
    end
    assert_match /Invalid variant/, e.message
  end
end
