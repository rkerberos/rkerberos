require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'rkerberos'
  spec.version    = '0.2.0'
  spec.authors    = ['Daniel Berger', 'Dominic Cleal', 'Simon Levermann']
  spec.license    = 'Artistic-2.0'
  spec.email      = ['djberg96@gmail.com', 'dominic@cleal.org', 'simon-rubygems@slevermann.de']
  spec.homepage   = 'http://github.com/rkerberos/rkerberos'
  spec.summary    = 'A Ruby interface for the the Kerberos library'
  spec.test_files = Dir['spec/**/*_spec.rb']
  spec.extensions = ['ext/rkerberos/extconf.rb']
  spec.files      = Dir['**/*'].grep_v(%r{\A(?:\.git|docker|Dockerfile)})

  spec.extra_rdoc_files = ['README.md', 'CHANGES', 'MANIFEST', 'LICENSE'] + Dir['ext/rkerberos/*.c']

  spec.add_development_dependency('rake-compiler')
  spec.add_development_dependency('rspec', '>= 3.0')
  spec.add_development_dependency('net-ldap')

  spec.description = <<-EOF
    The rkerberos library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.
  EOF

  spec.metadata = {
    'homepage_uri'          => 'https://github.com/rkerberos/rkerberos',
    'bug_tracker_uri'       => 'https://github.com/rkerberos/rkerberos/issues',
    'changelog_uri'         => 'https://github.com/rkerberos/rkerberos/blob/main/CHANGES.md',
    'documentation_uri'     => 'https://github.com/rkerberos/rkerberos/wiki',
    'source_code_uri'       => 'https://github.com/rkerberos/rkerberos',
    'wiki_uri'              => 'https://github.com/rkerberos/rkerberos/wiki',
    'github_repo'           => 'https://github.com/djberg96/rkerberos',
    'funding_uri'           => 'https://github.com/sponsors/rkerberos',
    'rubygems_mfa_required' => 'true'
  }
end
