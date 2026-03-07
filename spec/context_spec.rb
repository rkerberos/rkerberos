# spec/context_spec.rb
# RSpec tests for Kerberos::Krb5::Context

require 'rkerberos'

RSpec.describe Kerberos::Krb5::Context do
  subject(:context) { described_class.new }

  describe '#close' do
    it 'responds to close' do
      expect(context).to respond_to(:close)
    end
    it 'can be called without error' do
      expect { context.close }.not_to raise_error
    end
    it 'can be called multiple times without error' do
      expect { 3.times { context.close } }.not_to raise_error
    end
  end

  describe 'constructor options' do
    it 'accepts secure: true to use a secure context' do
      expect { described_class.new(secure: true) }.not_to raise_error
    end

    it 'accepts a profile path via :profile', :unix do
      profile_path = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
      expect(File).to exist(profile_path)
      expect { described_class.new(profile: profile_path) }.not_to raise_error
    end

    it 'validates profile argument type', :unix do
      expect { described_class.new(profile: 123) }.to raise_error(TypeError)
    end

    it 'ignores environment when secure: true' do
      begin
        orig = ENV['KRB5_CONFIG']
        ENV['KRB5_CONFIG'] = '/no/such/file'
        expect { described_class.new(secure: true) }.not_to raise_error
      ensure
        ENV['KRB5_CONFIG'] = orig
      end
    end

    it 'accepts secure: true together with profile', :unix do
      profile_path = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
      expect(File).to exist(profile_path)

      ctx = nil
      expect { ctx = described_class.new(secure: true, profile: profile_path) }.not_to raise_error
      expect(ctx).to be_a(described_class)
      expect { ctx.close }.not_to raise_error
    end
  end

  after(:each) do
    context.close
  end
end
