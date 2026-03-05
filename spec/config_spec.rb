# spec/config_spec.rb
# RSpec tests for Kerberos::Kadm5::Config

require 'spec_helper'

RSpec.describe 'config', :kadm5 do
  subject(:config) { Kerberos::Kadm5::Config.new }

  it 'is frozen' do
    expect(config).to be_frozen
  end

  describe 'realm' do
    it 'responds to realm' do
      expect(config).to respond_to(:realm)
    end

    it 'returns a String' do
      expect(config.realm).to be_a(String)
    end
  end

  describe 'kadmind_port' do
    it 'responds to kadmind_port' do
      expect(config).to respond_to(:kadmind_port)
    end

    it 'returns an Integer' do
      expect(config.kadmind_port).to be_a(Integer)
    end
  end

  describe 'kpasswd_port' do
    it 'responds to kpasswd_port' do
      expect(config).to respond_to(:kpasswd_port)
    end

    it 'returns an Integer' do
      expect(config.kpasswd_port).to be_a(Integer)
    end
  end

  describe 'admin_server' do
    it 'responds to admin_server' do
      expect(config).to respond_to(:admin_server)
    end

    it 'returns a String' do
      expect(config.admin_server).to be_a(String)
    end
  end

  describe 'acl_file' do
    it 'responds to acl_file' do
      expect(config).to respond_to(:acl_file)
    end

    it 'returns a String' do
      expect(config.acl_file).to be_a(String)
    end
  end

  describe 'dict_file' do
    it 'responds to dict_file' do
      expect(config).to respond_to(:dict_file)
    end

    it 'returns a String or nil' do
      expect([String, NilClass]).to include(config.dict_file.class)
    end
  end

  describe 'stash_file' do
    it 'responds to stash_file' do
      expect(config).to respond_to(:stash_file)
    end

    it 'returns a String or nil' do
      expect([String, NilClass]).to include(config.stash_file.class)
    end
  end

  describe 'mkey_name' do
    it 'responds to mkey_name' do
      expect(config).to respond_to(:mkey_name)
    end

    it 'returns a String or nil' do
      expect([String, NilClass]).to include(config.mkey_name.class)
    end
  end

  describe 'mkey_from_kbd' do
    it 'responds to mkey_from_kbd' do
      expect(config).to respond_to(:mkey_from_kbd)
    end

    it 'returns an Integer or nil' do
      expect([Integer, NilClass]).to include(config.mkey_from_kbd.class)
    end
  end

  describe 'enctype' do
    it 'responds to enctype' do
      expect(config).to respond_to(:enctype)
    end

    it 'returns an Integer' do
      expect(config.enctype).to be_a(Integer)
    end
  end

  describe 'max_life' do
    it 'responds to max_life' do
      expect(config).to respond_to(:max_life)
    end

    it 'returns an Integer' do
      expect(config.max_life).to be_a(Integer)
    end
  end

  describe 'max_rlife' do
    it 'responds to max_rlife' do
      expect(config).to respond_to(:max_rlife)
    end

    it 'returns an Integer' do
      expect(config.max_rlife).to be_a(Integer)
    end
  end

  describe 'expiration' do
    it 'responds to expiration' do
      expect(config).to respond_to(:expiration)
    end

    it 'returns a Time or nil' do
      expect([Time, NilClass]).to include(config.expiration.class)
    end
  end

  describe 'kvno' do
    it 'responds to kvno' do
      expect(config).to respond_to(:kvno)
    end

    it 'returns an Integer or nil' do
      expect([Integer, NilClass]).to include(config.kvno.class)
    end
  end

  describe 'iprop_enabled' do
    it 'responds to iprop_enabled' do
      expect(config).to respond_to(:iprop_enabled)
    end

    it 'returns a boolean' do
      expect(!!config.iprop_enabled == config.iprop_enabled).to be true
    end
  end

  describe 'iprop_logfile' do
    it 'responds to iprop_logfile' do
      expect(config).to respond_to(:iprop_logfile)
    end

    it 'returns a String' do
      expect(config.iprop_logfile).to be_a(String)
    end
  end

  describe 'iprop_poll_time' do
    it 'responds to iprop_poll_time' do
      expect(config).to respond_to(:iprop_poll_time)
    end

    it 'returns an Integer' do
      expect(config.iprop_poll_time).to be_a(Integer)
    end
  end

  describe 'iprop_port' do
    it 'responds to iprop_port' do
      expect(config).to respond_to(:iprop_port)
    end

    it 'returns an Integer or nil' do
      expect([Integer, NilClass]).to include(config.iprop_port.class)
    end
  end

  describe 'num_keysalts' do
    it 'responds to num_keysalts' do
      expect(config).to respond_to(:num_keysalts)
    end

    it 'returns an Integer' do
      expect(config.num_keysalts).to be_a(Integer)
    end
  end

  describe 'keysalts' do
    it 'responds to keysalts' do
      expect(config).to respond_to(:keysalts)
    end

    it 'returns an Array' do
      expect(config.keysalts).to be_a(Array)
    end

    it 'contains KeySalt objects if not empty' do
      unless config.keysalts.empty?
        expect(config.keysalts.first).to be_a(Kerberos::Kadm5::KeySalt)
      end
    end
  end
end
