# spec/krb5_keytab_spec.rb
# RSpec tests for Kerberos::Krb5::Keytab

require 'rkerberos'
require 'tmpdir'
require 'fileutils'

unless Gem.win_platform?
  require 'expect'
  require 'pty'
end

RSpec.describe Kerberos::Krb5::Keytab, :kadm5 do
  before(:all) do
    @realm = Kerberos::Kadm5::Config.new.realm
    @keytab_file = File.join(Dir.tmpdir, 'test.keytab')
    @keytab_name = "FILE:#{@keytab_file}"
    PTY.spawn('ktutil') do |reader, writer, _|
      reader.expect(/ktutil:\s+/)
      writer.puts("add_entry -password -p testuser1@#{@realm} -k 1 -e aes128-cts-hmac-sha1-96")
      reader.expect(/Password for testuser1@#{Regexp.quote(@realm)}:\s+/)
      writer.puts('asdfasdfasdf')
      reader.expect(/ktutil:\s+/)
      writer.puts("add_entry -password -p testuser2@#{@realm} -k 1 -e aes128-cts-hmac-sha1-96")
      reader.expect(/Password for testuser2@#{Regexp.quote(@realm)}:\s+/)
      writer.puts('asdfasdfasdf')
      reader.expect(/ktutil:\s+/)
      writer.puts("wkt #{@keytab_file}")
      reader.expect(/ktutil:\s+/)
    end
  end

  after(:all) do
    FileUtils.rm_f(@keytab_file)
  end

  subject(:keytab) { described_class.new }

  describe 'constructor' do
    it 'accepts an optional name' do
      expect { described_class.new("FILE:/usr/local/var/keytab") }.not_to raise_error
      expect { described_class.new("FILE:/bogus/keytab") }.not_to raise_error
    end

    it 'raises error for invalid residual type' do
      expect {
        described_class.new("BOGUS:/tmp/keytab")
      }.to raise_error(Kerberos::Krb5::Keytab::Exception)
    end
  end

  describe '#keytab_name and #keytab_type' do
    it 'returns the underlying name and type strings' do
      kt = described_class.new(@keytab_name)
      expect(kt).to respond_to(:keytab_name)
      expect(kt).to respond_to(:keytab_type)

      expect(kt.keytab_name).to be_a(String)
      expect(kt.keytab_type).to be_a(String)

      # name should include the residual portion we supplied
      expect(kt.keytab_name).to include(File.basename(@keytab_file))
      # type should match the scheme
      expect(kt.keytab_type.downcase).to eq("file")
    end
  end

  describe '#close' do
    it 'returns true' do
      kt = described_class.new(@keytab_name)
      expect(kt.close).to eq(true)
    end

    it 'can be called multiple times without error' do
      kt = described_class.new(@keytab_name)
      kt.close
      expect { kt.close }.not_to raise_error
    end

    it 'raises an error when calling keytab_name after close' do
      kt = described_class.new(@keytab_name)
      kt.close
      expect { kt.keytab_name }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'raises an error when calling keytab_type after close' do
      kt = described_class.new(@keytab_name)
      kt.close
      expect { kt.keytab_type }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'does not segfault when garbage collected after close' do
      kt = described_class.new(@keytab_name)
      kt.close
      kt = nil
      GC.start
    end
  end

  describe '.foreach' do
    it 'yields keytab entries for a valid keytab' do
      entries = []
      described_class.foreach(@keytab_name) { |entry| entries << entry }
      expect(entries.length).to eq(2)
      entries.each do |entry|
        expect(entry).to be_a(Kerberos::Krb5::Keytab::Entry)
        expect(entry.principal).to be_a(String)
        expect(entry.principal).to match(/@#{Regexp.quote(@realm)}$/)
        expect(entry.vno).to be_a(Integer)
        expect(entry.timestamp).to be_a(Time)
        expect(entry.key).to be_a(Integer)
      end
    end

    it 'uses the default keytab when no name is provided' do
      # The default keytab may not exist in the test container, so we
      # just verify it attempts to use it (raises keytab-related error
      # rather than ArgumentError or similar).
      begin
        described_class.foreach { |_| }
      rescue Kerberos::Krb5::Exception
        # Expected when default keytab is absent
      end
    end

    it 'raises an error for a non-existent keytab file' do
      expect {
        described_class.foreach("FILE:/no/such/keytab") { |_| }
      }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'raises an error for an invalid keytab type' do
      expect {
        described_class.foreach("BOGUS:/tmp/keytab") { |_| }
      }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'does not leak resources when the block raises' do
      expect {
        described_class.foreach(@keytab_name) { |_| raise "boom" }
      }.to raise_error(RuntimeError, "boom")
    end

    it 'does not leak resources when the block breaks' do
      result = catch(:done) do
        described_class.foreach(@keytab_name) { |_| throw :done, :escaped }
        :completed
      end
      expect(result).to eq(:escaped)
    end
  end

  describe '#each' do
    it 'yields keytab entries for a valid keytab' do
      kt = described_class.new(@keytab_name)
      entries = []
      kt.each { |entry| entries << entry }
      expect(entries.length).to eq(2)
      entries.each do |entry|
        expect(entry).to be_a(Kerberos::Krb5::Keytab::Entry)
        expect(entry.principal).to be_a(String)
        expect(entry.vno).to be_a(Integer)
        expect(entry.timestamp).to be_a(Time)
        expect(entry.key).to be_a(Integer)
      end
    end

    it 'does not leak resources when the block raises' do
      kt = described_class.new(@keytab_name)
      expect {
        kt.each { |_| raise "boom" }
      }.to raise_error(RuntimeError, "boom")
    end

    it 'does not leak resources when the block breaks' do
      kt = described_class.new(@keytab_name)
      result = catch(:done) do
        kt.each { |_| throw :done, :escaped }
        :completed
      end
      expect(result).to eq(:escaped)
    end
  end

  describe '#get_entry' do
    it 'finds an entry by principal name' do
      kt = described_class.new(@keytab_name)
      entry = kt.get_entry("testuser1@#{@realm}")
      expect(entry).to be_a(Kerberos::Krb5::Keytab::Entry)
      expect(entry.principal).to eq("testuser1@#{@realm}")
      expect(entry.vno).to eq(1)
      expect(entry.timestamp).to be_a(Time)
      expect(entry.key).to be_a(Integer)
    end

    it 'finds an entry filtering by vno' do
      kt = described_class.new(@keytab_name)
      entry = kt.get_entry("testuser1@#{@realm}", 1)
      expect(entry.principal).to eq("testuser1@#{@realm}")
      expect(entry.vno).to eq(1)
    end

    it 'finds an entry filtering by vno and enctype' do
      kt = described_class.new(@keytab_name)
      # aes128-cts-hmac-sha1-96 is enctype 17
      entry = kt.get_entry("testuser1@#{@realm}", 1, 17)
      expect(entry.principal).to eq("testuser1@#{@realm}")
      expect(entry.vno).to eq(1)
      expect(entry.key).to eq(17)
    end

    it 'raises an error for a non-existent principal' do
      kt = described_class.new(@keytab_name)
      expect {
        kt.get_entry("bogus@#{@realm}")
      }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'is aliased as find' do
      kt = described_class.new(@keytab_name)
      expect(kt.method(:find)).to eq(kt.method(:get_entry))
    end
  end

  describe '#dup' do
    it 'creates an independent handle referring to same keytab' do
      kt1 = described_class.new(@keytab_name)
      kt2 = kt1.dup
      expect(kt2).to be_a(described_class)
      expect(kt2.keytab_name).to eq(kt1.keytab_name)

      # closing one should not invalidate the other
      kt1.close
      expect { kt2.keytab_name }.not_to raise_error
    end

    it 'clone is an alias for dup' do
      kt = described_class.new(@keytab_name)
      expect(kt.method(:clone)).to eq(kt.method(:dup))
    end
  end
end
