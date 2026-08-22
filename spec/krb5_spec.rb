# spec/krb5_spec.rb
# RSpec tests for Kerberos::Krb5

require 'spec_helper'
require 'open3'

unless File::ALT_SEPARATOR
  require 'pty'
  require 'expect'
end

RSpec.describe Kerberos::Krb5 do
  before(:all) do
    krb5_conf = RSpec.configuration.krb5_conf
    @cache_found = true
    Open3.popen3('klist') { |_, _, stderr| @cache_found = false unless stderr.gets.nil? }
    @realm = IO.read(krb5_conf).split("\n").grep(/default_realm/).first.split('=').last.lstrip.chomp
  end

  subject(:krb5) { described_class.new }
  let(:keytab) { Kerberos::Krb5::Keytab.new.default_name.split(':').last }
  let(:user) { "testuser1@#{@realm}" }
  let(:service) { 'kadmin/admin' }

  it 'has the correct version constant' do
    expect(Kerberos::Krb5::VERSION).to eq('0.3.1')
  end

  it 'accepts a block and yields itself' do
    expect { described_class.new {} }.not_to raise_error
    described_class.new { |k| expect(k).to be_a(described_class) }
  end

  describe 'constructor' do
    it 'accepts a context keyword argument' do
      context = Kerberos::Krb5::Context.new
      k = described_class.new(context: context)
      expect(k).to be_a(described_class)
      expect(k.get_default_realm).to eq(@realm)
      k.close
    end

    it 'raises TypeError if context is not a Kerberos::Krb5::Context' do
      expect { described_class.new(context: 'bad') }.to raise_error(TypeError, /context must be/)
    end

    it 'raises an error if the context is closed' do
      context = Kerberos::Krb5::Context.new
      context.close
      expect { described_class.new(context: context) }.to raise_error(Kerberos::Krb5::Exception, /context is closed/)
    end

    it 'rejects positional option hashes and unknown keywords' do
      expect { described_class.new({context: nil}) }.to raise_error(ArgumentError)
      expect { described_class.new(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end
  end

  describe '#get_default_realm' do
    it 'responds to get_default_realm' do
      expect(krb5).to respond_to(:get_default_realm)
    end
    it 'can be called without error' do
      expect { krb5.get_default_realm }.not_to raise_error
      expect(krb5.get_default_realm).to be_a(String)
    end
    it 'takes no arguments' do
      expect { krb5.get_default_realm('localhost') }.to raise_error(ArgumentError)
    end
    it 'matches the realm from krb5.conf' do
      expect(krb5.get_default_realm).to eq(@realm)
    end
    it 'default_realm is an alias for get_default_realm' do
      expect(krb5.method(:default_realm)).to eq(krb5.method(:get_default_realm))
    end
    it 'raises after the object is closed' do
      krb5.close
      expect { krb5.get_default_realm }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  describe '#set_default_realm' do
    it 'raises after the object is closed' do
      krb5.close
      expect { krb5.set_default_realm(@realm) }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  describe '#verify_init_creds', :kadm5 do
    # Some KDC setups may not correctly set the initial password during
    # entrypoint startup; enforce it here via the admin API so the test is
    # deterministic.
    before do
      user = "testuser1@#{@realm}"
      Kerberos::Kadm5.new(
        principal: ENV.fetch('KRB5_ADMIN_PRINCIPAL', 'admin/admin@EXAMPLE.COM'),
        password: ENV.fetch('KRB5_ADMIN_PASSWORD', 'adminpassword')
      ) do |kadmin|
        kadmin.set_password(user, 'changeme')
      end
    end

    it 'responds to verify_init_creds' do
      expect(krb5).to respond_to(:verify_init_creds)
    end

    it 'requires get_init_creds_password arguments as keywords' do
      expect { krb5.get_init_creds_password(user, 'changeme') }.to raise_error(ArgumentError)
      expect {
        krb5.get_init_creds_password(principal: user, password: 'changeme', unknown: true)
      }.to raise_error(ArgumentError, /unknown keyword/)
    end

    it 'raises when no credentials have been acquired' do
      expect { krb5.verify_init_creds }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'validates argument types' do
      expect { krb5.verify_init_creds(server: true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(keytab: true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(ccache: true) }.to raise_error(TypeError)
    end

    it 'accepts only documented keyword arguments' do
      expect { krb5.verify_init_creds(nil) }.to raise_error(ArgumentError)
      expect { krb5.verify_init_creds(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end

    it 'verifies credentials obtained via password' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts a server principal string' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      expect(krb5.verify_init_creds(server: "kadmin/admin@#{@realm}")).to be true
    end

    it 'accepts a Keytab object' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      kt = Kerberos::Krb5::Keytab.new
      expect(krb5.verify_init_creds(keytab: kt)).to be true
    end

    it 'rejects a closed Keytab object' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      kt = Kerberos::Krb5::Keytab.new
      kt.close
      expect { krb5.verify_init_creds(keytab: kt) }
        .to raise_error(Kerberos::Krb5::Exception, /keytab is closed/)
    end

    it 'stores additional credentials in provided CredentialsCache' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      expect(krb5.verify_init_creds(ccache: ccache)).to be true
      expect(ccache.primary_principal).to be_a(String)
      expect(ccache.primary_principal).to include('@')
    end

    it 'rejects a closed CredentialsCache' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      ccache = Kerberos::Krb5::CredentialsCache.new
      ccache.close
      expect { krb5.verify_init_creds(ccache: ccache) }
        .to raise_error(Kerberos::Krb5::Exception, /credentials cache is closed/)
    end

    it 'does not acquire credentials into a closed CredentialsCache' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      ccache.close
      expect {
        krb5.get_init_creds_password(principal: user, password: 'changeme', ccache: ccache)
      }.to raise_error(Kerberos::Krb5::Exception, /credentials cache is closed/)
    end

    it 'provides authenticate! which acquires and verifies (Zanarotti mitigation)' do
      expect(krb5).to respond_to(:authenticate!)
      expect(krb5.authenticate!(principal: user, password: 'changeme')).to be true
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts an optional service argument' do
      expect {
        krb5.authenticate!(principal: user, password: 'changeme', service: 'verify/rkerberos-test')
      }.not_to raise_error
    end

    it 'fails closed when no verification keytab is available' do
      original_keytab = ENV['KRB5_KTNAME']
      ENV['KRB5_KTNAME'] = "FILE:/tmp/missing_verify_keytab_#{Process.pid}"

      expect {
        described_class.new.authenticate!(principal: user, password: 'changeme')
      }.to raise_error(Kerberos::Krb5::Exception, /krb5_verify_init_creds/)
    ensure
      ENV['KRB5_KTNAME'] = original_keytab
    end

    it 'validates argument types for authenticate!' do
      expect { krb5.authenticate!(principal: true, password: true) }.to raise_error(TypeError)
    end

    it 'requires authenticate! arguments as keywords' do
      expect { krb5.authenticate!(user, 'changeme') }.to raise_error(ArgumentError)
      expect {
        krb5.authenticate!(principal: user, password: 'changeme', unknown: true)
      }.to raise_error(ArgumentError, /unknown keyword/)
    end
  end

  describe '#change_password', :kadm5 do
    before do
      # Ensure testuser1 has a known password before each test.
      Kerberos::Kadm5.new(
        principal: ENV.fetch('KRB5_ADMIN_PRINCIPAL', 'admin/admin@EXAMPLE.COM'),
        password: ENV.fetch('KRB5_ADMIN_PASSWORD', 'adminpassword')
      ) do |kadmin|
        kadmin.set_password(user, 'changeme')
      end
    end

    after do
      # Reset to known password so later tests are not affected.
      Kerberos::Kadm5.new(
        principal: ENV.fetch('KRB5_ADMIN_PRINCIPAL', 'admin/admin@EXAMPLE.COM'),
        password: ENV.fetch('KRB5_ADMIN_PASSWORD', 'adminpassword')
      ) do |kadmin|
        kadmin.set_password(user, 'changeme')
      end
    end

    it 'responds to change_password' do
      expect(krb5).to respond_to(:change_password)
    end

    it 'requires exactly two arguments' do
      expect { krb5.change_password }.to raise_error(ArgumentError)
      expect { krb5.change_password('old') }.to raise_error(ArgumentError)
      expect { krb5.change_password('old', 'new', 'extra') }.to raise_error(ArgumentError)
    end

    it 'raises if no principal has been established' do
      expect { krb5.change_password('changeme', 'newpass1A!') }.to raise_error(Kerberos::Krb5::Exception, /no principal/)
    end

    it 'changes the password successfully' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      expect(krb5.change_password('changeme', 'Newpass99!')).to be true
      # Verify we can authenticate with the new password
      krb5_check = described_class.new
      expect(krb5_check.get_init_creds_password(principal: user, password: 'Newpass99!')).to be true
      krb5_check.close
    end

    it 'raises with a meaningful message when the old password is wrong' do
      krb5.get_init_creds_password(principal: user, password: 'changeme')
      expect {
        krb5.change_password('wrongpass', 'Newpass99!')
      }.to raise_error(Kerberos::Krb5::Exception, /krb5_(get_init_creds_password|change_password)/)
    end

    it 'requires string arguments' do
      expect { krb5.change_password(1, 'new') }.to raise_error(TypeError)
      expect { krb5.change_password('old', 1) }.to raise_error(TypeError)
    end

    context 'when the KDC rejects the new password due to policy' do
      let(:policy_user) { "policyuser@#{@realm}" }
      # Password must satisfy strict_policy (minlength=8, minclasses=3).
      let(:compliant_pw) { 'Changeme1!' }

      it 'raises an exception with the KDC rejection reason' do
        krb5.get_init_creds_password(principal: policy_user, password: compliant_pw)
        expect {
          krb5.change_password(compliant_pw, 'a')
        }.to raise_error(Kerberos::Krb5::Exception, /krb5_change_password/)
      end
    end
  end

  describe '#get_init_creds_keytab', :unix do
    before(:each) do
      @kt_file = File.join(Dir.tmpdir, "test_get_init_creds_#{Process.pid}_#{rand(10000)}.keytab")

      PTY.spawn('ktutil') do |reader, writer, _|
        reader.expect(/ktutil:\s+/)
        writer.puts("add_entry -password -p testuser1@#{@realm} -k 1 -e aes128-cts-hmac-sha1-96")
        reader.expect(/Password for #{Regexp.quote("testuser1@#{@realm}")}:\s+/)
        writer.puts('changeme')
        reader.expect(/ktutil:\s+/)
        writer.puts("wkt #{@kt_file}")
        reader.expect(/ktutil:\s+/)
        writer.puts('quit')
      end
    end

    it 'responds to get_init_creds_keytab' do
      expect(krb5).to respond_to(:get_init_creds_keytab)
    end

    it 'accepts only documented keyword arguments' do
      expect { krb5.get_init_creds_keytab(user) }.to raise_error(ArgumentError)
      expect { krb5.get_init_creds_keytab(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end

    it 'acquires credentials for a principal from a supplied keytab file' do
      kt_name = "FILE:#{@kt_file}"
      expect { krb5.get_init_creds_keytab(principal: user, keytab: kt_name) }.not_to raise_error
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts a CredentialsCache to receive credentials' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      kt_name = "FILE:#{@kt_file}"
      expect { krb5.get_init_creds_keytab(principal: user, keytab: kt_name, ccache: ccache) }.not_to raise_error
      expect(ccache.primary_principal).to be_a(String)
      expect(ccache.primary_principal).to include('@')
    end

    it 'rejects a closed CredentialsCache' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      ccache.close
      kt_name = "FILE:#{@kt_file}"
      expect {
        krb5.get_init_creds_keytab(principal: user, keytab: kt_name, ccache: ccache)
      }.to raise_error(Kerberos::Krb5::Exception, /credentials cache is closed/)
    end
  end

  describe '.thread_safe?' do
    it 'returns a boolean' do
      result = described_class.thread_safe?
      expect([true, false]).to include(result)
    end

    it 'is callable without an instance' do
      expect(described_class).to respond_to(:thread_safe?)
    end
  end

  describe '#get_host_realm' do
    it 'responds to get_host_realm' do
      expect(krb5).to respond_to(:get_host_realm)
    end

    it 'returns an array of realm strings' do
      result = krb5.get_host_realm('localhost')
      expect(result).to be_a(Array)
      result.each { |r| expect(r).to be_a(String) }
    end

    it 'returns a non-empty array for a known hostname' do
      result = krb5.get_host_realm('localhost')
      expect(result).not_to be_empty
    end

    it 'raises TypeError for non-string argument' do
      expect { krb5.get_host_realm(123) }.to raise_error(TypeError)
    end

    it 'raises ArgumentError when called without arguments' do
      expect { krb5.get_host_realm }.to raise_error(ArgumentError)
    end
  end

  describe '#expand_hostname' do
    it 'responds to expand_hostname' do
      expect(krb5).to respond_to(:expand_hostname)
    end

    it 'returns a string' do
      result = krb5.expand_hostname('localhost')
      expect(result).to be_a(String)
    end

    it 'returns a non-empty string' do
      result = krb5.expand_hostname('localhost')
      expect(result.size).to be > 0
    end

    it 'raises TypeError for non-string argument' do
      expect { krb5.expand_hostname(123) }.to raise_error(TypeError)
    end

    it 'raises ArgumentError when called without arguments' do
      expect { krb5.expand_hostname }.to raise_error(ArgumentError)
    end
  end
end
