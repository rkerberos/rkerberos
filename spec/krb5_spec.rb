# spec/krb5_spec.rb
# RSpec tests for Kerberos::Krb5

require 'rkerberos'
require 'open3'
require 'pty'
require 'expect'

RSpec.describe Kerberos::Krb5 do
  before(:all) do
    @cache_found = true
    Open3.popen3('klist') { |_, _, stderr| @cache_found = false unless stderr.gets.nil? }
    @krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    @realm = IO.read(@krb5_conf).split("\n").grep(/default_realm/).first.split('=').last.lstrip.chomp

  end

  subject(:krb5) { described_class.new }
  let(:keytab) { Kerberos::Krb5::Keytab.new.default_name.split(':').last }
  let(:user) { "testuser1@#{@realm}" }
  let(:service) { 'kadmin/admin' }

  it 'has the correct version constant' do
    expect(Kerberos::Krb5::VERSION).to eq('0.2.0')
  end

  it 'accepts a block and yields itself' do
    expect { described_class.new {} }.not_to raise_error
    described_class.new { |k| expect(k).to be_a(described_class) }
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
  end

  describe '#verify_init_creds' do
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

    it 'raises when no credentials have been acquired' do
      expect { krb5.verify_init_creds }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'validates argument types' do
      expect { krb5.verify_init_creds(true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(nil, true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(nil, nil, true) }.to raise_error(TypeError)
    end

    it 'verifies credentials obtained via password' do
      krb5.get_init_creds_password(user, 'changeme')
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts a server principal string' do
      krb5.get_init_creds_password(user, 'changeme')
      expect(krb5.verify_init_creds("kadmin/admin@#{@realm}")).to be true
    end

    it 'accepts a Keytab object' do
      krb5.get_init_creds_password(user, 'changeme')
      kt = Kerberos::Krb5::Keytab.new
      expect(krb5.verify_init_creds(nil, kt)).to be true
    end

    it 'stores additional credentials in provided CredentialsCache' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      krb5.get_init_creds_password(user, 'changeme')
      expect(krb5.verify_init_creds(nil, nil, ccache)).to be true
      expect(ccache.primary_principal).to be_a(String)
      expect(ccache.primary_principal).to include('@')
    end

    it 'provides authenticate! which acquires and verifies (Zanarotti mitigation)' do
      expect(krb5).to respond_to(:authenticate!)
      expect(krb5.authenticate!(user, 'changeme')).to be true
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts an optional service argument' do
      expect { krb5.authenticate!(user, 'changeme', 'kadmin/changepw') }.not_to raise_error
      expect(krb5.verify_init_creds).to be true
    end

    it 'validates argument types for authenticate!' do
      expect { krb5.authenticate!(true, true) }.to raise_error(TypeError)
    end
  end

  describe '#get_init_creds_keytab' do
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

    it 'acquires credentials for a principal from a supplied keytab file' do
      kt_name = "FILE:#{@kt_file}"
      expect { krb5.get_init_creds_keytab(user, kt_name) }.not_to raise_error
      expect(krb5.verify_init_creds).to be true
    end

    it 'accepts a CredentialsCache to receive credentials' do
      ccache = Kerberos::Krb5::CredentialsCache.new
      kt_name = "FILE:#{@kt_file}"
      expect { krb5.get_init_creds_keytab(user, kt_name, nil, ccache) }.not_to raise_error
      expect(ccache.primary_principal).to be_a(String)
      expect(ccache.primary_principal).to include('@')
    end
  end
end
