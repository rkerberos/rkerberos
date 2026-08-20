require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'rkerberos'
  spec.version    = '0.3.0'
  spec.authors    = ['Daniel Berger', 'Dominic Cleal', 'Simon Levermann']
  spec.license    = 'Artistic-2.0'
  spec.email      = ['djberg96@gmail.com', 'dominic@cleal.org', 'simon-rubygems@slevermann.de']
  spec.homepage   = 'https://github.com/rkerberos/rkerberos'
  spec.summary    = 'A Ruby interface for the Kerberos library'
  spec.required_ruby_version = '>= 3.2'
  spec.test_files = Dir['spec/**/*_spec.rb']
  spec.extensions = ['ext/rkerberos/extconf.rb']
  spec.files      = Dir['**/*']
    .select { |file| File.file?(file) }
    .grep_v(%r{\A(?:\.git|docker|Dockerfile|Gemfile\.lock\z|tmp(?:/|\z))|\.gem\z})

  spec.add_development_dependency('rake-compiler')
  spec.add_development_dependency('rspec', '>= 3.0')
  spec.add_development_dependency('net-ldap')

  spec.description = <<-EOF
    The rkerberos library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.
  EOF

  spec.metadata = {
    'bug_tracker_uri'       => 'https://github.com/rkerberos/rkerberos/issues',
    'changelog_uri'         => 'https://github.com/rkerberos/rkerberos/blob/master/CHANGES.md',
    'documentation_uri'     => 'https://github.com/rkerberos/rkerberos/wiki',
    'source_code_uri'       => 'https://github.com/rkerberos/rkerberos',
    'github_repo'           => 'https://github.com/rkerberos/rkerberos',
    'funding_uri'           => 'https://github.com/sponsors/rkerberos',
    'rubygems_mfa_required' => 'true'
  }
end
