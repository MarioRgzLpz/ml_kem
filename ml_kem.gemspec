# frozen_string_literal: true

require_relative "lib/ml_kem/version"

Gem::Specification.new do |spec|
  spec.name = "ml_kem"
  spec.version = MLKEM::VERSION
  spec.authors = ["MarioRgzLpz"]
  spec.email = ["MarioRgzLpz@correo.ugr.es"]

  spec.summary = "Implementation of ML-KEM (Kyber) post-quantum cryptography algorithm."
  spec.description = "A Ruby gem providing an implementation of the ML-KEM (formerly Kyber) key-encapsulation mechanism for post-quantum cryptography standards."
  spec.homepage = "https://github.com/MarioRgzLpz/ml_kem" 
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"
  spec.metadata["homepage_uri"] = spec.homepage 
  spec.metadata["source_code_uri"] = "https://github.com/MarioRgzLpz/ml_kem" 

  gemspec = File.basename(__FILE__)
  spec.files = Dir[
    "lib/**/*",
    "exe/**/*",
    "README*",
    "LICENSE*",
  ]
  spec.bindir = "exe"
  spec.executables = ["mlkem"]
  spec.require_paths = ["lib"]

  spec.add_dependency "sha3", "~> 2.2.2"
  spec.add_dependency "thor", "~> 1.3.2"
  
  spec.add_development_dependency "yard", "~> 0.9.37"
  spec.add_development_dependency "minitest", "~> 5.25.5"
  spec.add_development_dependency "rake", "~> 13.3.0"
  spec.add_development_dependency "irb", "~> 1.15.2"
end
