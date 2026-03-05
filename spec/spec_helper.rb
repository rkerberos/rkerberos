# spec/spec_helper.rb

require 'rspec'
require 'rkerberos'

# Exclude admin/kadm5 specs if not available
RSpec.configure do |config|
  config.filter_run_excluding :kadm5 => true unless defined?(Kerberos::Kadm5::Config)
end
