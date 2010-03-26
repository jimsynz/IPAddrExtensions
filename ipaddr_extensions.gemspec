# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ipaddr_extensions}
  s.version = "2010.3.26"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["James Harton"]
  s.date = %q{2010-03-26}
  s.email = %q{jamesotron@gmail.com}
  s.files = ["MPL-LICENSE", "README", "Rakefile", "init.rb", "install.rb", "ipaddr_extensions.gemspec", "lib/ip_addr_extensions.rb", "tasks/ip_addr_extensions_tasks.rake", "test/ip_addr_extensions_test.rb", "test/test_helper.rb", "uninstall.rb"]
  s.has_rdoc = false
  s.homepage = %q{http://github.com/jamesotron/IPAddrExtensions}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{A small gem that adds extra functionality to Rubys IPAddr class}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
