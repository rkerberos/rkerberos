require 'rspec'

RSpec.configure do |config|
  config.filter_run_excluding :kadm5 => true unless defined?(Kerberos::Kadm5::Config)
  config.filter_run_excluding :unix => true if File::ALT_SEPARATOR

  default_conf = ENV['KRB5_CONFIG'] || (
    File::ALT_SEPARATOR ?
      'C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini' :
      '/etc/krb5.conf'
  )

  unless File.exist?(default_conf)
    config.filter_run_excluding :krb5_config => true
  end
end
