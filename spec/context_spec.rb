# spec/context_spec.rb
# RSpec tests for Kerberos::Krb5::Context

require 'spec_helper'

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

    it 'raises while a dependent wrapper remains open' do
      krb5 = Kerberos::Krb5.new(context: context)

      expect { context.close }
        .to raise_error(Kerberos::Krb5::Exception, /1 dependent wrapper/)
      expect(context.default_realm).to be_a(String)

      krb5.close
      expect { context.close }.not_to raise_error
    end

    it 'tracks multiple dependent wrappers independently' do
      first = Kerberos::Krb5.new(context: context)
      second = Kerberos::Krb5::Principal.new(name: 'user', context: context)

      expect { context.close }
        .to raise_error(Kerberos::Krb5::Exception, /2 dependent wrappers/)

      first.close
      expect { context.close }
        .to raise_error(Kerberos::Krb5::Exception, /1 dependent wrapper/)

      second.close
      expect { context.close }.not_to raise_error
    end

    it 'supports a forced logical close with deferred native cleanup' do
      krb5 = Kerberos::Krb5.new(context: context)
      realm = krb5.default_realm

      expect(context.close(force: true)).to equal(context)
      expect { context.default_realm }.to raise_error(Kerberos::Krb5::Exception)
      expect { Kerberos::Krb5.new(context: context) }
        .to raise_error(Kerberos::Krb5::Exception, /context is closed/)
      expect(krb5.default_realm).to eq(realm)

      expect { krb5.close }.not_to raise_error
      expect { context.close }.not_to raise_error
    end

    it 'requires close options to be keywords and rejects unknown keywords' do
      expect { context.close({force: true}) }.to raise_error(ArgumentError)
      expect { context.close(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end
  end

  describe 'constructor options' do
    let(:profile_path){ RSpec.configuration.krb5_conf }

    it 'accepts secure: true to use a secure context' do
      expect { described_class.new(secure: true) }.not_to raise_error
    end

    it 'accepts a profile path via :profile', :unix do
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
      expect(File).to exist(profile_path)
      ctx = nil
      expect { ctx = described_class.new(secure: true, profile: profile_path) }.not_to raise_error
      expect(ctx).to be_a(described_class)
      expect { ctx.close }.not_to raise_error
    end

    it 'rejects positional option hashes and unknown keywords' do
      expect { described_class.new({secure: true}) }.to raise_error(ArgumentError)
      expect { described_class.new(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end
  end

  describe '#default_realm' do
    it 'responds to default_realm' do
      expect(context).to respond_to(:default_realm)
    end

    it 'returns a string' do
      expect(context.default_realm).to be_a(String)
    end

    it 'returns a non-empty realm' do
      expect(context.default_realm.size).to be > 0
    end

    it 'raises when context is closed' do
      context.close
      expect { context.default_realm }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  describe '#default_realm=' do
    it 'responds to default_realm=' do
      expect(context).to respond_to(:default_realm=)
    end

    it 'can set and read back a custom realm' do
      context.default_realm = 'TEST.REALM'
      expect(context.default_realm).to eq('TEST.REALM')
    end

    it 'accepts nil to reset to the default' do
      original = context.default_realm
      context.default_realm = 'TEMP.REALM'
      context.default_realm = nil
      expect(context.default_realm).to eq(original)
    end

    it 'raises TypeError for non-string argument' do
      expect { context.default_realm = 123 }.to raise_error(TypeError)
    end

    it 'raises when context is closed' do
      context.close
      expect { context.default_realm = 'X' }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  after(:each) do
    context.close
  end
end
