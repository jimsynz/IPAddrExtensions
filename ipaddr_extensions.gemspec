# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ipaddr_extensions}
  s.version = "2011.6.30"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["James Harton"]
  s.date = %q{2011-06-30}
  s.email = %q{james@sociable.co.nz}
  s.files = ["MPL-LICENSE", "README", "Rakefile", "init.rb", "install.rb", "ipaddr_extensions.gemspec", "lib/ipaddr_extensions.rb", "tasks/ipaddr_extensions_tasks.rake", "test/ipaddr_extensions_test.rb", "test/test_helper.rb", "uninstall.rb"]
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
