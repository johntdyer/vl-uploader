# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'vl/uploader/version'

Gem::Specification.new do |spec|
  spec.name          = "vl-uploader"
  spec.version       = Vl::Uploader::VERSION
  spec.authors       = ["John Dyer"]
  spec.email         = ["jdyer@voxeolabs.com"]
  spec.description   = %q{TODO: Write a gem description}
  spec.summary       = %q{TODO: Write a gem summary}
  spec.homepage      = "https://github.com/johntdyer/vl-uploader"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "s3"
  spec.add_dependency "mime-types"
  spec.add_development_dependency "bundler", "~> 1.3"

  spec.add_development_dependency "rake"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "flexmock"
  spec.add_development_dependency "fakeweb"
  spec.add_development_dependency "fakefs"
  spec.add_development_dependency "logger"
  spec.add_development_dependency "json_spec"
  spec.add_development_dependency "timecop"
  spec.add_development_dependency "simplecov"

end
