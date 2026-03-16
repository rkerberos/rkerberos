# spec/kadm5_spec.rb
# RSpec tests for Kerberos::Kadm5

require 'spec_helper'
require 'socket'
require 'fileutils'

RSpec.describe 'Kerberos::Kadm5', :kadm5 do
  let(:server){ Kerberos::Kadm5::Config.new.admin_server }
  subject(:klass){ Kerberos::Kadm5 }

  before(:all) do
    @host = Socket.gethostname
    @user = ENV['KRB5_ADMIN_PRINCIPAL']
    @pass = ENV['KRB5_ADMIN_PASSWORD']
    @krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    ENV['KRB5_CONFIG'] = @krb5_conf
    @test_princ = 'zztop'
    @test_policy = 'test_policy'
  end

  let(:user) { @user }
  let(:pass) { @pass }
  let(:test_princ) { @test_princ }
  let(:test_policy) { @test_policy }

  describe 'constructor' do
    it 'responds to .new' do
      expect(subject).to respond_to(:new)
    end

    it 'works with valid user and password' do
      expect { subject.new(principal: user, password: pass) }.not_to raise_error
    end

    it 'works with valid service' do
      expect {
        subject.new(principal: user, password: pass, service: 'kadmin/admin')
      }.not_to raise_error
    end

    it 'only accepts a hash argument' do
      expect { subject.new(user) }.to raise_error(TypeError)
      expect { subject.new(1) }.to raise_error(TypeError)
    end

    it 'accepts a block and yields itself' do
      expect { subject.new(principal: user, password: pass) {} }.not_to raise_error
      subject.new(principal: user, password: pass) { |kadm5| expect(kadm5).to be_a(subject) }
    end

    it 'requires principal to be specified' do
      expect { subject.new({}) }.to raise_error(ArgumentError)
    end

    it 'requires principal to be a string' do
      expect { subject.new(principal: 1, password: pass) }.to raise_error(TypeError)
    end

    it 'requires password to be a string' do
      expect { subject.new(principal: user, password: 1) }.to raise_error(TypeError)
    end

    it 'requires keytab to be a string or boolean' do
      expect { subject.new(principal: user, keytab: 1) }.to raise_error(TypeError)
    end

    it 'requires service to be a string' do
      expect { subject.new(principal: user, password: pass, service: 1) }.to raise_error(TypeError)
    end

    it 'accepts a context keyword argument' do
      ctx = Kerberos::Krb5::Context.new
      expect { subject.new(principal: user, password: pass, context: ctx) }.not_to raise_error
    end

    it 'raises TypeError for non-Context context argument' do
      expect { subject.new(principal: user, password: pass, context: "bad") }.to raise_error(TypeError)
    end

    it 'raises error for a closed context' do
      ctx = Kerberos::Krb5::Context.new
      ctx.close
      expect { subject.new(principal: user, password: pass, context: ctx) }.to raise_error(Kerberos::Krb5::Exception)
    end

    context 'with a credentials cache', :cache do
      let(:krb5) { Kerberos::Krb5.new }
      let(:cache_path) { "/tmp/test_kadm5_ccache_#{Process.pid}" }
      let(:cache_name) { "FILE:#{cache_path}" }
      let(:cache) { Kerberos::Krb5::CredentialsCache.new(cache_name: cache_name) }

      before(:each) do
        krb5.get_init_creds_password(user, pass)
        krb5.verify_init_creds(ccache: cache)
      end

      after(:each) do
        ccache.close rescue nil
        krb5.close rescue nil
        FileUtils.rm_f([cache_path, "#{cache_path}.lock"])
      end

      it 'works with a populated credentials cache' do
        expect { subject.new(principal: user, ccache: cache) }.not_to raise_error
      end

      it 'returns a Kadm5 object' do
        kadm5 = subject.new(principal: user, ccache: cache)
        expect(kadm5).to be_a(subject)
        kadm5.close
      end

      it 'can perform operations after ccache authentication' do
        kadm5 = subject.new(principal: user, ccache: cache)
        privs = kadm5.get_privileges
        expect(privs).to be_a(Integer)
        expect(privs).not_to eq(0)
        kadm5.close
      end

      it 'raises TypeError if ccache is not a CredentialsCache' do
        expect {
          subject.new(principal: user, ccache: "not_a_ccache")
        }.to raise_error(TypeError)
      end

      it 'raises an error for a destroyed credentials cache' do
        dead_ccache = Kerberos::Krb5::CredentialsCache.new
        dead_ccache.destroy
        expect {
          subject.new(principal: user, ccache: dead_ccache)
        }.to raise_error(Kerberos::Krb5::Exception)
      end

      it 'raises ArgumentError when both password and ccache are given' do
        expect {
          subject.new(principal: user, password: pass, ccache: cache)
        }.to raise_error(ArgumentError)
      end

      it 'raises ArgumentError when both keytab and ccache are given' do
        expect {
          subject.new(principal: user, keytab: true, ccache: cache)
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe '#get_privileges' do
    before(:each) do
      @kadm5 = subject.new(principal: user, password: pass)
    end

    after(:each) do
      @kadm5.close
    end

    it 'returns an integer bitmask by default' do
      result = @kadm5.get_privileges
      expect(result).to be_a(Integer)
      expect(result).not_to eq(0)
    end

    it 'returns an array of strings when passed a truthy argument' do
      result = @kadm5.get_privileges(true)
      expect(result).to be_a(Array)
      expect(result).not_to be_empty
      expect(result).to all(be_a(String))
    end

    it 'only contains valid privilege names' do
      result = @kadm5.get_privileges(true)
      valid = %w[GET ADD MODIFY DELETE]
      result.each do |priv|
        expect(valid).to include(priv)
      end
    end

    it 'does not contain UNKNOWN entries' do
      result = @kadm5.get_privileges(true)
      expect(result).not_to include('UNKNOWN')
    end

    it 'includes GET for an admin principal' do
      result = @kadm5.get_privileges(true)
      expect(result).to include('GET')
    end
  end

  describe '#create_principal' do
    before(:each) do
      @kadm5 = subject.new(principal: user, password: pass)
      @realm = Kerberos::Kadm5::Config.new.realm
      @created = []
    end

    after(:each) do
      @created.each do |name|
        @kadm5.delete_principal(name) rescue nil
      end
      @kadm5.close
    end

    it 'creates a principal with name: and password:' do
      pname = "create_test1@#{@realm}"
      @kadm5.create_principal(name: pname, password: 'Test1234!')
      @created << pname
      p = @kadm5.find_principal(pname)
      expect(p).to be_a(Kerberos::Krb5::Principal)
      expect(p.principal).to eq(pname)
    end

    it 'returns self for chaining' do
      pname = "create_test2@#{@realm}"
      result = @kadm5.create_principal(name: pname, password: 'Test1234!')
      @created << pname
      expect(result).to equal(@kadm5)
    end

    it 'accepts a nil db_args option' do
      pname = "create_test3@#{@realm}"
      expect {
        @kadm5.create_principal(name: pname, password: 'Test1234!', db_args: nil)
      }.not_to raise_error
      @created << pname
    end

    it 'raises ArgumentError when password: is missing' do
      expect {
        @kadm5.create_principal(name: "create_nopass@#{@realm}")
      }.to raise_error(ArgumentError)
    end

    it 'raises ArgumentError when neither name: nor principal: is given' do
      expect {
        @kadm5.create_principal(password: 'Test1234!')
      }.to raise_error(ArgumentError)
    end

    it 'raises ArgumentError with no arguments' do
      expect {
        @kadm5.create_principal
      }.to raise_error(ArgumentError)
    end

    it 'raises ArgumentError when both name: and principal: are given' do
      p = Kerberos::Krb5::Principal.new(name: "create_both@#{@realm}")
      expect {
        @kadm5.create_principal(name: "create_both@#{@realm}", principal: p, password: 'Test1234!')
      }.to raise_error(ArgumentError)
    end

    it 'raises an error for a duplicate principal' do
      pname = "create_dup@#{@realm}"
      @kadm5.create_principal(name: pname, password: 'Test1234!')
      @created << pname
      expect {
        @kadm5.create_principal(name: pname, password: 'Test1234!')
      }.to raise_error(Kerberos::Kadm5::Exception)
    end

    context 'with a Principal object' do
      it 'creates a principal from a Principal object' do
        pname = "create_obj1@#{@realm}"
        p = Kerberos::Krb5::Principal.new(name: pname)
        @kadm5.create_principal(principal: p, password: 'Test1234!')
        @created << pname
        found = @kadm5.find_principal(pname)
        expect(found).to be_a(Kerberos::Krb5::Principal)
        expect(found.principal).to eq(pname)
      end

      it 'raises TypeError if principal: is not a Principal object' do
        expect {
          @kadm5.create_principal(principal: "notaobj", password: 'Test1234!')
        }.to raise_error(TypeError)
      end

      it 'raises ArgumentError if the principal has no name' do
        p = Kerberos::Krb5::Principal.new
        expect {
          @kadm5.create_principal(principal: p, password: 'Test1234!')
        }.to raise_error(ArgumentError)
      end

      it 'forwards the policy attribute' do
        pname = "create_pol@#{@realm}"
        p = Kerberos::Krb5::Principal.new(name: pname)
        p.policy = 'strict_policy'
        @kadm5.create_principal(principal: p, password: 'Changeme1!')
        @created << pname
        found = @kadm5.find_principal(pname)
        expect(found.policy).to eq('strict_policy')
      end

      it 'forwards expire_time' do
        pname = "create_exp@#{@realm}"
        p = Kerberos::Krb5::Principal.new(name: pname)
        future = Time.now + 86400 * 365
        p.expire_time = future
        @kadm5.create_principal(principal: p, password: 'Test1234!')
        @created << pname
        found = @kadm5.find_principal(pname)
        # Allow a small delta for timestamp rounding
        expect(found.expire_time.to_i).to be_within(1).of(future.to_i)
      end

      it 'forwards max_life' do
        pname = "create_maxlife@#{@realm}"
        p = Kerberos::Krb5::Principal.new(name: pname)
        p.max_life = 7200
        @kadm5.create_principal(principal: p, password: 'Test1234!')
        @created << pname
        found = @kadm5.find_principal(pname)
        expect(found.max_life).to eq(7200)
      end

      it 'forwards max_renewable_life' do
        pname = "create_maxrenew@#{@realm}"
        p = Kerberos::Krb5::Principal.new(name: pname)
        p.max_renewable_life = 14400
        @kadm5.create_principal(principal: p, password: 'Test1234!')
        @created << pname
        found = @kadm5.find_principal(pname)
        expect(found.max_renewable_life).to eq(14400)
      end
    end
  end
end
