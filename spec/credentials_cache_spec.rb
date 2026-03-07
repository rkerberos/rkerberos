# spec/credentials_cache_spec.rb
# RSpec tests for Kerberos::Krb5::CredentialsCache
require 'spec_helper'
require 'rkerberos'
require 'etc'
require 'open3'
require 'tmpdir'

RSpec.describe Kerberos::Krb5::CredentialsCache, :unix, :krb5_config do
  let(:login) do
    Etc.getlogin || ENV['USER'] || (Etc.getpwuid(Process.uid).name rescue nil)
  end

  let(:realm) { Kerberos::Krb5.new.default_realm }
  let(:princ) { "#{login}@#{realm}" }
  let(:cfile) { File.join(Dir.tmpdir, "krb5cc_#{Etc.getpwnam(login).uid}") }
  let(:ccache) { described_class.new }

  def cache_found?
    found = true
    Open3.popen3('klist') { |_, _, stderr| found = false unless stderr.gets.nil? }
    found
  end

  after(:each) do
    Open3.popen3('kdestroy') { sleep 0.1 }
  end

  describe 'constructor' do
    it 'can be called with no arguments' do
      expect { described_class.new }.not_to raise_error
    end

    it 'does not create a cache with no arguments' do
      described_class.new
      expect(File.exist?(cfile)).to be false
      expect(cache_found?).to be false
    end
    it 'creates a cache with a principal' do
      expect { described_class.new(princ) }.not_to raise_error
      expect(File.exist?(cfile)).to be true
      expect(cache_found?).to be true
    end
    it 'accepts an explicit cache name' do
      expect { described_class.new(princ, cfile) }.not_to raise_error
      expect { described_class.new(nil, cfile) }.not_to raise_error
    end
    it 'raises error for non-string argument' do
      expect { described_class.new(true) }.to raise_error(TypeError)
    end
    it 'accepts only up to two arguments' do
      expect { described_class.new(princ, cfile, cfile) }.to raise_error(ArgumentError)
    end
  end

  describe '#close' do
    it 'responds to close' do
      expect(described_class.new(princ)).to respond_to(:close)
    end
    it 'does not delete credentials cache' do
      c = described_class.new(princ)
      expect { c.close }.not_to raise_error
      expect(cache_found?).to be true
    end
    it 'can be called multiple times without error' do
      c = described_class.new(princ)
      expect { 3.times { c.close } }.not_to raise_error
    end
    it 'raises error when calling method on closed object' do
      c = described_class.new(princ)
      c.close
      expect { c.default_name }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  describe '#default_name' do
    it 'responds to default_name' do
      c = described_class.new(princ)
      expect(c).to respond_to(:default_name)
      expect { c.default_name }.not_to raise_error
    end
    it 'returns a string' do
      c = described_class.new(princ)
      expect(c.default_name).to be_a(String)
    end
  end

  describe '#cache_name and #cache_type' do
    it 'returns the ccache name and type' do
      c = described_class.new(princ)
      expect(c).to respond_to(:cache_name)
      expect(c).to respond_to(:cache_type)

      expect(c.cache_name).to be_a(String)
      expect(c.cache_type).to be_a(String)

      # cache_name returns the residual portion of the cache name; default_name
      # may include the type prefix (e.g. "FILE:"). ensure the suffix matches.
      expect(c.cache_name).to eq(c.default_name.split(':').last)
    end
  end

  describe '#principal' do
    it 'is an alias for primary_principal' do
      c = described_class.new(princ)
      expect(c).to respond_to(:principal)
      expect(c.principal).to eq(c.primary_principal)
    end
  end

  describe '#primary_principal' do
    it 'responds to primary_principal' do
      c = described_class.new(princ)
      expect(c).to respond_to(:primary_principal)
      expect { c.primary_principal }.not_to raise_error
    end
    it 'returns expected results' do
      c = described_class.new(princ)
      expect(c.primary_principal).to be_a(String)
      expect(c.primary_principal.size).to be > 0
      expect(c.primary_principal).to include('@')
    end
  end

  describe '#destroy' do
    it 'responds to destroy' do
      c = described_class.new(princ)
      expect(c).to respond_to(:destroy)
    end
    it 'deletes credentials cache' do
      c = described_class.new(princ)
      expect { c.destroy }.not_to raise_error
      expect(cache_found?).to be false
    end
    it 'delete is an alias for destroy' do
      c = described_class.new(princ)
      expect(c).to respond_to(:delete)
      expect(c.method(:delete)).to eq(c.method(:destroy))
    end
    it 'returns false if no credentials cache' do
      c = described_class.new
      expect(c.destroy).to be false
    end
    it 'raises error when calling method on destroyed object' do
      c = described_class.new(princ)
      c.destroy
      expect { c.default_name }.to raise_error(Kerberos::Krb5::Exception)
    end
    it 'does not accept arguments' do
      c = described_class.new(princ)
      expect { c.destroy(true) }.to raise_error(ArgumentError)
    end
  end

  describe '#dup' do
    it 'returns a new cache object with the same properties' do
      c = described_class.new(princ)
      c2 = c.dup
      expect(c2).to be_a(described_class)
      expect(c2.default_name).to eq(c.default_name)
      expect(c2.primary_principal).to eq(c.primary_principal)
    end

    it 'closing original does not affect duplicate' do
      c = described_class.new(princ)
      c2 = c.dup
      c.close
      expect { c2.default_name }.not_to raise_error
    end

    it 'closing duplicate does not affect original' do
      c = described_class.new(princ)
      c2 = c.dup
      c2.close
      expect { c.default_name }.not_to raise_error
    end

    it 'raises when duping closed cache' do
      c = described_class.new(princ)
      c.close
      expect { c.dup }.to raise_error(Kerberos::Krb5::Exception)
    end
  end
end
