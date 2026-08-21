# spec/principal_spec.rb
# RSpec tests for Kerberos::Krb5::Principal

require 'rkerberos'

RSpec.describe Kerberos::Krb5::Principal do
  let(:name) { 'Jon' }
  subject(:princ) { described_class.new(name: name) }

  describe 'constructor' do
    it 'requires name to be a string' do
      expect { described_class.new(name: 1) }.to raise_error(TypeError)
      expect { described_class.new(name: true) }.to raise_error(TypeError)
    end

    it 'accepts no arguments' do
      expect{ described_class.new }.not_to raise_error
    end

    it 'works as expected with no name argument' do
      expect(described_class.new.principal).to be_nil
    end

    it 'rejects positional arguments' do
      expect { described_class.new('Jon') }.to raise_error(ArgumentError)
    end

    it 'accepts a context keyword argument' do
      ctx = Kerberos::Krb5::Context.new
      expect { described_class.new(name: 'Jon', context: ctx) }.not_to raise_error
    end

    it 'rejects positional option hashes and unknown keywords' do
      expect { described_class.new({name: 'Jon'}) }.to raise_error(ArgumentError)
      expect { described_class.new(unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end

    it 'uses the same realm when a context is provided' do
      ctx = Kerberos::Krb5::Context.new
      p1 = described_class.new(name: 'Jon')
      p2 = described_class.new(name: 'Jon', context: ctx)
      expect(p2.realm).to eq(p1.realm)
    end

    it 'raises TypeError for non-Context context argument' do
      expect { described_class.new(name: 'Jon', context: "bad") }.to raise_error(TypeError)
    end

    it 'raises error for a closed context' do
      ctx = Kerberos::Krb5::Context.new
      ctx.close
      expect { described_class.new(name: 'Jon', context: ctx) }.to raise_error(Kerberos::Krb5::Exception)
    end
  end

  describe '#realm' do
    it 'returns the expected value' do
      expect(subject.realm).to eq('EXAMPLE.COM')
    end

    it 'raises an error if no name was provided' do
      expect{ described_class.new.realm }.to raise_error(Kerberos::Krb5::Exception, /no principal/)
    end
  end

  describe '#==' do
    it 'returns true for equivalent principals' do
      expect(princ).to eq(described_class.new(name: name))
    end

    it 'returns false for objects of another type' do
      expect(princ == name).to be false
      expect(princ == nil).to be false
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

  describe '#principal_type' do
    it 'returns an integer for a named principal' do
      p = described_class.new(name: 'user@EXAMPLE.COM')
      expect(p.principal_type).to be_a(Integer)
    end

    it 'returns KRB5_NT_PRINCIPAL (1) for a simple name' do
      p = described_class.new(name: 'user@EXAMPLE.COM')
      expect(p.principal_type).to eq(1)
    end

    it 'raises an error when no principal has been established' do
      p = described_class.new
      expect { p.principal_type }.to raise_error(Kerberos::Krb5::Exception, /no principal/)
    end
  end

  describe '#components' do
    it 'responds to components' do
      expect(princ).to respond_to(:components)
    end

    it 'returns an array of strings' do
      result = princ.components
      expect(result).to be_a(Array)
      result.each { |c| expect(c).to be_a(String) }
    end

    it 'returns one component for a simple principal' do
      p = described_class.new(name: 'user@EXAMPLE.COM')
      expect(p.components).to eq(['user'])
    end

    it 'returns multiple components for a compound principal' do
      p = described_class.new(name: 'admin/instance@EXAMPLE.COM')
      expect(p.components).to eq(['admin', 'instance'])
    end

    it 'returns three components for a three-part principal' do
      p = described_class.new(name: 'a/b/c@EXAMPLE.COM')
      expect(p.components).to eq(['a', 'b', 'c'])
    end

    it 'raises an error when no principal has been established' do
      p = described_class.new
      expect { p.components }.to raise_error(Kerberos::Krb5::Exception, /no principal/)
    end
  end
end
