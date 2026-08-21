# spec/policy_spec.rb
# RSpec tests for Kerberos::Kadm5::Policy

require 'spec_helper'

RSpec.describe 'Kerberos::Kadm5::Policy', :kadm5 do
  subject(:klass){ Kerberos::Kadm5::Policy }
  let(:policy) { klass.new(name: 'test', max_life: 10000) }

  describe 'name' do
    it 'responds to policy' do
      expect(policy).to respond_to(:policy)
    end
    it 'responds to name (alias)' do
      expect(policy).to respond_to(:name)
      expect(policy.method(:name)).to eq(policy.method(:policy))
    end
    it 'must be a string' do
      expect { klass.new(name: 1) }.to raise_error(TypeError)
    end
    it 'must be present' do
      expect { klass.new(max_life: 10000) }.to raise_error(ArgumentError)
    end
    it 'rejects positional option hashes and unknown keywords' do
      expect { klass.new({name: 'test'}) }.to raise_error(ArgumentError)
      expect { klass.new(name: 'test', unknown: true) }.to raise_error(ArgumentError, /unknown keyword/)
    end
  end

  describe 'min_life' do
    it 'responds to min_life' do
      expect(policy).to respond_to(:min_life)
      expect { policy.min_life }.not_to raise_error
    end
    it 'must be a number if not nil' do
      expect { klass.new(name: 'test', min_life: 'test') }.to raise_error(TypeError)
    end
  end

  describe 'max_life' do
    it 'responds to max_life' do
      expect(policy).to respond_to(:max_life)
      expect { policy.max_life }.not_to raise_error
    end
    it 'must be a number if not nil' do
      expect { klass.new(name: 'test', max_life: 'test') }.to raise_error(TypeError)
    end
  end

  describe 'min_length' do
    it 'responds to min_length' do
      expect(policy).to respond_to(:min_length)
      expect { policy.min_length }.not_to raise_error
    end
  end
end
