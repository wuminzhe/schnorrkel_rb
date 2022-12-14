# frozen_string_literal: true

require_relative "lib/schnorrkel_rb/version"

Gem::Specification.new do |spec|
  spec.name = "schnorrkel_rb"
  spec.version = SchnorrkelRb::VERSION
  spec.authors = ["Aki Wu"]
  spec.email = ["wuminzhe@gmail.com"]

  spec.summary = "Ruby SR25519 Signature"
  spec.description = "A Ruby wrapper to the Rust schnorrkel SR25519 signature library."
  spec.homepage = "https://github.com/wuminzhe/schnorrkel_rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org/"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.extensions << "ext/Rakefile"
  spec.add_runtime_dependency "thermite", "~> 0"
  spec.add_dependency "ffi", "~> 1.0"
end
