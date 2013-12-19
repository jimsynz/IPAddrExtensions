# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)

Gem::Specification.new do |s|
  s.name          = 'ipaddr_extensions'
  s.version       = '1.0.1'
  s.platform      = Gem::Platform::RUBY
  s.authors       = ["James Harton"]
  s.email         = %q{james@resistor.io}
  s.homepage      = %q{http://github.com/jamesotron/IPAddrExtensions}
  s.summary       = %q{A small gem that adds extra functionality to Rubys IPAddr class}

  s.files         = ["MIT-LICENSE", "README", "Rakefile", "ipaddr_extensions.gemspec"] + Dir["lib/**/*"]
  s.require_paths = ["lib"]

  s.add_development_dependency 'rake'
end
