# spec/kadm5_spec.rb
# RSpec tests for Kerberos::Kadm5

require 'rkerberos'
require 'socket'

RSpec.describe 'admin', :kadm5 do
  subject(:klass){ Kerberos::Kadm5 }
  let(:server){ Kerberos::Kadm5::Config.new.admin_server }

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
      expect(klass).to respond_to(:new)
    end
    it 'works with valid user and password' do
      expect { klass.new(principal: user, password: pass) }.not_to raise_error
    end
    it 'works with valid service' do
      expect {
        klass.new(principal: user, password: pass, service: 'kadmin/admin')
      }.not_to raise_error
    end
    it 'only accepts a hash argument' do
      expect { klass.new(user) }.to raise_error(TypeError)
      expect { klass.new(1) }.to raise_error(TypeError)
    end
    it 'accepts a block and yields itself' do
      expect { klass.new(principal: user, password: pass) {} }.not_to raise_error
      klass.new(principal: user, password: pass) { |kadm5| expect(kadm5).to be_a(klass) }
    end
    it 'requires principal to be specified' do
      expect { klass.new({}) }.to raise_error(ArgumentError)
    end
    it 'requires principal to be a string' do
      expect { klass.new(principal: 1) }.to raise_error(TypeError)
    end
    it 'requires password to be a string' do
      expect { klass.new(principal: user, password: 1) }.to raise_error(TypeError)
    end
    it 'requires keytab to be a string or boolean' do
      expect { klass.new(principal: user, keytab: 1) }.to raise_error(TypeError)
    end
    it 'requires service to be a string' do
      expect { klass.new(principal: user, password: pass, service: 1) }.to raise_error(TypeError)
    end
  end

  describe '#get_privileges' do
    before(:each) do
      @kadm5 = described_class.new(principal: user, password: pass)
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
end
