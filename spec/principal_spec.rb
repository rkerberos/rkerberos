# spec/principal_spec.rb
# RSpec tests for Kerberos::Krb5::Principal
require 'spec_helper'
require 'rkerberos'

RSpec.describe Kerberos::Krb5::Principal, :krb5_config do
  let(:name) { 'Jon' }
  subject(:princ) { described_class.new(name) }

  describe 'constructor' do
    it 'requires a string argument' do
      expect { described_class.new(1) }.to raise_error(TypeError)
      expect { described_class.new(true) }.to raise_error(TypeError)
    end

    it 'accepts an explicit nil argument' do
      expect{ described_class.new(nil) }.not_to raise_error
    end

    it 'works as expected with a nil argument to the constructor' do
      expect(described_class.new(nil).principal).to be_nil
    end
  end

  describe '#realm' do
    it 'returns the expected value' do
      expect(subject.realm).to eq('EXAMPLE.COM')
    end

    it 'raises an error if the constructor argument was nil' do
      expect{ described_class.new(nil).realm }.to raise_error(Kerberos::Krb5::Exception, /no principal/)
    end
  end

  describe '#name' do
    it 'responds to name' do
      expect(princ).to respond_to(:name)
      expect { princ.name }.not_to raise_error
    end
    it 'returns expected results' do
      expect(princ.name).to eq('Jon')
    end
  end

  describe '#expire_time' do
    it 'responds to expire_time' do
      expect(princ).to respond_to(:expire_time)
      expect { princ.expire_time }.not_to raise_error
    end
  end

  describe '#last_password_change' do
    it 'responds to last_password_change' do
      expect(princ).to respond_to(:last_password_change)
      expect { princ.last_password_change }.not_to raise_error
    end
  end

  describe '#password_expiration' do
    it 'responds to password_expiration' do
      expect(princ).to respond_to(:password_expiration)
      expect { princ.password_expiration }.not_to raise_error
    end
  end

  describe '#max_life' do
    it 'responds to max_life' do
      expect(princ).to respond_to(:max_life)
      expect { princ.max_life }.not_to raise_error
    end
  end

  describe '#mod_name' do
    it 'responds to mod_name' do
      expect(princ).to respond_to(:mod_name)
      expect { princ.mod_name }.not_to raise_error
    end
  end

  describe '#mod_date' do
    it 'responds to mod_date' do
      expect(princ).to respond_to(:mod_date)
      expect { princ.mod_date }.not_to raise_error
    end
  end
end
