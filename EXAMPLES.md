# rkerberos Usage Examples

This page provides comprehensive examples for each class in the rkerberos library. All examples assume you have already installed the gem and have a working Kerberos environment.

```ruby
require 'rkerberos'
```

---

## Table of Contents

- [Kerberos::Krb5](#kerberoskrb5)
- [Kerberos::Krb5::Context](#kerberoskrb5context)
- [Kerberos::Krb5::CredentialsCache](#kerberoskrb5credentialscache)
- [Kerberos::Krb5::Keytab](#kerberoskrb5keytab)
- [Kerberos::Krb5::Keytab::Entry](#kerberoskrb5keytabentry)
- [Kerberos::Krb5::Principal](#kerberoskrb5principal)
- [Kerberos::Kadm5](#kerberoskadm5)
- [Kerberos::Kadm5::Config](#kerberoskadm5config)
- [Kerberos::Kadm5::Policy](#kerberoskadm5policy)
- [Constants](#constants)
- [Error Handling](#error-handling)

---

## Kerberos::Krb5

The main class for Kerberos client operations: authentication, credential acquisition, realm queries, and password management.

### Creating an Instance

```ruby
# Simple instantiation
krb5 = Kerberos::Krb5.new

# Block form — automatically closes when the block exits
Kerberos::Krb5.new do |krb5|
  puts krb5.default_realm
end
```

### Querying the Default Realm

```ruby
krb5 = Kerberos::Krb5.new
puts krb5.default_realm  # => "EXAMPLE.COM"
krb5.close
```

### Setting the Default Realm

```ruby
krb5 = Kerberos::Krb5.new
krb5.set_default_realm('OTHER.REALM.COM')
puts krb5.default_realm  # => "OTHER.REALM.COM"

# Reset to the default from krb5.conf
krb5.set_default_realm
krb5.close
```

### Authenticating with a Password

```ruby
krb5 = Kerberos::Krb5.new

# Basic password authentication
krb5.get_init_creds_password('user@EXAMPLE.COM', 's3cret')

# With an explicit service
krb5.get_init_creds_password('user@EXAMPLE.COM', 's3cret', 'krbtgt/EXAMPLE.COM')

krb5.close
```

### Secure Authentication (authenticate!)

The `authenticate!` method acquires credentials **and** verifies them against the KDC, protecting against KDC-forging attacks. This is the recommended method for login flows.

```ruby
krb5 = Kerberos::Krb5.new

begin
  krb5.authenticate!('user@EXAMPLE.COM', 's3cret')
  puts "Authentication successful"
rescue Kerberos::Krb5::Exception => e
  puts "Authentication failed: #{e.message}"
end

krb5.close
```

### Authenticating with a Keytab

```ruby
krb5 = Kerberos::Krb5.new

# Using the default keytab (/etc/krb5.keytab)
krb5.get_init_creds_keytab('host/server.example.com')

# Using a specific keytab file
krb5.get_init_creds_keytab('host/server.example.com', 'FILE:/etc/app.keytab')

# With a specific service name
krb5.get_init_creds_keytab('host/server.example.com', nil, 'host')

# Store the resulting credentials in a cache
cc = Kerberos::Krb5::CredentialsCache.new
krb5.get_init_creds_keytab('host/server.example.com', nil, nil, cc)

krb5.close
```

### Verifying Credentials

After acquiring credentials, you can explicitly verify them against the KDC:

```ruby
krb5 = Kerberos::Krb5.new
krb5.get_init_creds_password('user@EXAMPLE.COM', 's3cret')

# Basic verification
krb5.verify_init_creds

# Verify against a specific server principal
krb5.verify_init_creds('host/server.example.com@EXAMPLE.COM')

# Verify using a specific keytab and store results in a credential cache
keytab = Kerberos::Krb5::Keytab.new
cc = Kerberos::Krb5::CredentialsCache.new
krb5.verify_init_creds(nil, keytab, cc)
puts cc.primary_principal  # => "user@EXAMPLE.COM"

krb5.close
```

### Changing a Password

```ruby
krb5 = Kerberos::Krb5.new

# First authenticate the user
krb5.get_init_creds_password('user@EXAMPLE.COM', 'old_password')

# Then change the password
krb5.change_password('old_password', 'new_password')

krb5.close
```

### Getting the Default Principal

Returns the principal from the default credentials cache:

```ruby
krb5 = Kerberos::Krb5.new
puts krb5.default_principal  # => "user@EXAMPLE.COM"
krb5.close
```

### Listing Permitted Encryption Types

```ruby
krb5 = Kerberos::Krb5.new
enctypes = krb5.get_permitted_enctypes

enctypes.each do |code, description|
  puts "#{code}: #{description}"
end
# Example output:
#   17: AES-128 CTS mode with 96-bit SHA-1 HMAC
#   18: AES-256 CTS mode with 96-bit SHA-1 HMAC
#   23: ArcFour with HMAC/md5

krb5.close
```

### Version

```ruby
puts Kerberos::Krb5::VERSION  # => "0.2.3"
```

---

## Kerberos::Krb5::Context

A lightweight Kerberos context object. Useful when you need a context for configuration queries without full credential management.

### Standard Context

```ruby
ctx = Kerberos::Krb5::Context.new
# ... use ctx ...
ctx.close
```

### Secure Context

A secure context ignores environment variables like `KRB5_CONFIG` and reads only from system configuration files. Use this in setuid programs or other security-sensitive environments.

```ruby
ctx = Kerberos::Krb5::Context.new(secure: true)
ctx.close
```

### Context with a Custom Profile

Load configuration from a specific krb5.conf file:

```ruby
ctx = Kerberos::Krb5::Context.new(profile: '/opt/custom/krb5.conf')
ctx.close
```

### Combining Options

```ruby
ctx = Kerberos::Krb5::Context.new(profile: '/opt/custom/krb5.conf', secure: true)
ctx.close
```

---

## Kerberos::Krb5::CredentialsCache

Encapsulates a Kerberos credentials cache (ccache). Used for storing and managing TGTs and service tickets.

### Using the Default Cache

```ruby
cc = Kerberos::Krb5::CredentialsCache.new
puts cc.default_name  # => "FILE:/tmp/krb5cc_1000"

cc.close
```

### Creating a Cache with a Specific Principal

```ruby
# Creates (or reinitializes) the default cache with this principal
cc = Kerberos::Krb5::CredentialsCache.new('user@EXAMPLE.COM')
puts cc.primary_principal  # => "user@EXAMPLE.COM"

cc.close
```

### Using a Named Cache

```ruby
# Use a specific cache file
cc = Kerberos::Krb5::CredentialsCache.new(nil, 'FILE:/tmp/krb5cc_myapp')
puts cc.cache_name  # => "/tmp/krb5cc_myapp"
puts cc.cache_type  # => "FILE"

cc.close
```

### Querying Cache Properties

```ruby
cc = Kerberos::Krb5::CredentialsCache.new

puts cc.default_name       # Default cache path for the system
puts cc.cache_name         # Actual name of this cache instance
puts cc.cache_type         # Cache type, e.g. "FILE", "MEMORY", "KCM"
puts cc.primary_principal  # The principal stored in this cache
puts cc.principal          # Alias for primary_principal

cc.close
```

### Duplicating a Cache

```ruby
cc = Kerberos::Krb5::CredentialsCache.new('user@EXAMPLE.COM')
cc2 = cc.dup  # Independent copy; closing one does not affect the other

cc.close
cc2.close
```

### Destroying a Cache

Destroys the cache file and invalidates the object. Returns `true` if the cache was destroyed or `false` if no cache was found.

```ruby
cc = Kerberos::Krb5::CredentialsCache.new('user@EXAMPLE.COM')
cc.destroy  # => true (also aliased as cc.delete)
```

### Storing Verified Credentials in a Cache

```ruby
krb5 = Kerberos::Krb5.new
cc = Kerberos::Krb5::CredentialsCache.new

krb5.get_init_creds_password('user@EXAMPLE.COM', 's3cret')
krb5.verify_init_creds(nil, nil, cc)

puts cc.primary_principal  # => "user@EXAMPLE.COM"

cc.close
krb5.close
```

---

## Kerberos::Krb5::Keytab

Provides access to Kerberos keytab files for reading entries and performing keytab-based authentication.

### Opening the Default Keytab

```ruby
keytab = Kerberos::Krb5::Keytab.new
puts keytab.name          # => "FILE:/etc/krb5.keytab"
puts keytab.default_name  # => "FILE:/etc/krb5.keytab"
puts keytab.keytab_name   # Canonical name from the library
puts keytab.keytab_type   # => "FILE"

keytab.close
```

### Opening a Specific Keytab

```ruby
keytab = Kerberos::Krb5::Keytab.new('FILE:/etc/app.keytab')
puts keytab.name  # => "FILE:/etc/app.keytab"

keytab.close
```

### Iterating Over Entries

```ruby
keytab = Kerberos::Krb5::Keytab.new

keytab.each do |entry|
  puts "Principal: #{entry.principal}"
  puts "Timestamp: #{entry.timestamp}"
  puts "Version:   #{entry.vno}"
  puts "Key Type:  #{entry.key}"
  puts "---"
end

keytab.close
```

### Using the Singleton foreach Method

Iterate over keytab entries without creating an instance:

```ruby
# Default keytab
Kerberos::Krb5::Keytab.foreach do |entry|
  puts entry.principal
end

# Specific keytab
Kerberos::Krb5::Keytab.foreach('FILE:/etc/app.keytab') do |entry|
  puts entry.principal
end
```

### Looking Up a Specific Entry

```ruby
keytab = Kerberos::Krb5::Keytab.new

# Find the first entry matching a principal
entry = keytab.get_entry('host/server.example.com@EXAMPLE.COM')
puts entry.principal
puts entry.vno

# Find with a specific version number
entry = keytab.get_entry('host/server.example.com@EXAMPLE.COM', 2)

# Find with a specific version number and encryption type
entry = keytab.get_entry(
  'host/server.example.com@EXAMPLE.COM',
  0,
  Kerberos::Krb5::ENCTYPE_AES256_CTS_HMAC_SHA1_96
)

keytab.close
```

### Duplicating a Keytab

```ruby
keytab = Kerberos::Krb5::Keytab.new
keytab2 = keytab.dup  # Independent handle; closing one doesn't affect the other

keytab.close
keytab2.close
```

---

## Kerberos::Krb5::Keytab::Entry

Represents a single entry in a keytab. These objects are yielded by `Keytab#each` and `Keytab.foreach`, or returned by `Keytab#get_entry`.

### Attributes

```ruby
keytab = Kerberos::Krb5::Keytab.new

keytab.each do |entry|
  entry.principal  # => "host/server.example.com@EXAMPLE.COM"
  entry.timestamp  # => 2026-03-01 12:00:00 -0500 (Time object)
  entry.vno        # => 1 (key version number)
  entry.key        # => 18 (encryption type, e.g. AES-256)
end

keytab.close
```

### Inspecting an Entry

```ruby
keytab = Kerberos::Krb5::Keytab.new

entry = keytab.get_entry('host/server.example.com@EXAMPLE.COM')
puts entry.inspect
# => #<Kerberos::Krb5::Keytab::Entry principal="host/server.example.com@EXAMPLE.COM" timestamp=2026-03-01 12:00:00 -0500 vno=1 key=18>

keytab.close
```

---

## Kerberos::Krb5::Principal

Represents a Kerberos principal with associated metadata. Typically returned by `Kadm5#get_principal` or `Kadm5#find_principal`, but can also be created standalone.

### Creating a Principal

```ruby
principal = Kerberos::Krb5::Principal.new('user@EXAMPLE.COM')
puts principal.principal  # => "user@EXAMPLE.COM"
puts principal.name       # => "user@EXAMPLE.COM" (alias)
puts principal.realm      # => "EXAMPLE.COM"
```

### Using a Block

```ruby
principal = Kerberos::Krb5::Principal.new('user@EXAMPLE.COM') do |p|
  p.expire_time = Time.now + 86400 * 365
  p.max_life = 36000
end
```

### Changing the Realm

```ruby
principal = Kerberos::Krb5::Principal.new('user@EXAMPLE.COM')
puts principal.realm  # => "EXAMPLE.COM"

principal.realm = 'OTHER.REALM.COM'
puts principal.realm  # => "OTHER.REALM.COM"
```

### Comparing Principals

```ruby
p1 = Kerberos::Krb5::Principal.new('user@EXAMPLE.COM')
p2 = Kerberos::Krb5::Principal.new('user@EXAMPLE.COM')
p3 = Kerberos::Krb5::Principal.new('admin@EXAMPLE.COM')

p1 == p2  # => true
p1 == p3  # => false
```

### Attributes from Kadm5

When retrieved via `Kadm5#get_principal`, the Principal object is populated with additional metadata:

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  princ = kadm5.get_principal('user@EXAMPLE.COM')

  puts princ.principal              # => "user@EXAMPLE.COM"
  puts princ.attributes             # => Bitmask of principal flags
  puts princ.aux_attributes         # => Auxiliary attributes
  puts princ.expire_time            # => Time or nil
  puts princ.fail_auth_count        # => Integer
  puts princ.kvno                   # => Key version number
  puts princ.last_failed            # => Time or nil
  puts princ.last_password_change   # => Time or nil
  puts princ.last_success           # => Time or nil
  puts princ.max_life               # => Max ticket life in seconds
  puts princ.max_renewable_life     # => Max renewable life in seconds
  puts princ.mod_date               # => Time or nil
  puts princ.mod_name               # => "admin/admin@EXAMPLE.COM"
  puts princ.password_expiration    # => Time or nil
  puts princ.policy                 # => "default" or nil
end
```

---

## Kerberos::Kadm5

The admin interface for managing principals, policies, and passwords. Requires admin credentials.

### Connecting with a Password

```ruby
# Block form (recommended) — automatically closes when done
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # ... admin operations ...
end

# Manual form
kadm5 = Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass')
# ... admin operations ...
kadm5.close
```

### Connecting with a Keytab

```ruby
# Using the default keytab (/etc/krb5.keytab)
Kerberos::Kadm5.new(principal: 'admin/admin', keytab: true) do |kadm5|
  # ...
end

# Using a specific keytab file
Kerberos::Kadm5.new(principal: 'admin/admin', keytab: '/etc/admin.keytab') do |kadm5|
  # ...
end
```

### Specifying a Custom Service

```ruby
Kerberos::Kadm5.new(
  principal: 'admin/admin',
  password: 'admin_pass',
  service: 'kadmin/changepw'
) do |kadm5|
  # ...
end
```

### Using Database Arguments

```ruby
# Single db_arg
Kerberos::Kadm5.new(
  principal: 'admin/admin',
  password: 'admin_pass',
  db_args: 'tktpolicy=default'
) do |kadm5|
  # ...
end

# Multiple db_args
Kerberos::Kadm5.new(
  principal: 'admin/admin',
  password: 'admin_pass',
  db_args: ['arg1=value1', 'arg2=value2']
) do |kadm5|
  # ...
end
```

### Creating a Principal

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  kadm5.create_principal('newuser@EXAMPLE.COM', 'initial_password')

  # With database arguments
  kadm5.create_principal('ldapuser@EXAMPLE.COM', 'password', 'tktpolicy=default')
end
```

### Deleting a Principal

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  kadm5.delete_principal('newuser@EXAMPLE.COM')
end
```

### Getting Principal Information

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Raises PrincipalNotFoundException if not found
  princ = kadm5.get_principal('user@EXAMPLE.COM')
  puts princ.inspect
end
```

### Finding a Principal (nil if not found)

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  princ = kadm5.find_principal('user@EXAMPLE.COM')

  if princ
    puts princ.principal
  else
    puts "Principal not found"
  end
end
```

### Listing Principals

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # List all principals
  all = kadm5.get_principals
  all.each { |name| puts name }

  # List principals matching a pattern
  matches = kadm5.get_principals('host/*')
  matches.each { |name| puts name }

  # Other pattern examples
  kadm5.get_principals('user*')       # Starts with "user"
  kadm5.get_principals('*/admin@*')   # Admin instances
end
```

### Setting a Password

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  kadm5.set_password('user@EXAMPLE.COM', 'new_password')
end
```

### Setting Password Expiration

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Set password to expire at a specific Unix timestamp
  expire_time = (Time.now + 86400 * 90).to_i  # 90 days from now
  kadm5.set_pwexpire('user@EXAMPLE.COM', expire_time)
end
```

### Generating Random Keys

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  num_keys = kadm5.generate_random_key('host/server.example.com@EXAMPLE.COM')
  puts "Generated #{num_keys} random key(s)"
end
```

### Checking Admin Privileges

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Get privileges as a bitmask
  privs = kadm5.get_privileges
  puts privs  # => 15 (all privileges)

  # Get privileges as human-readable strings
  privs = kadm5.get_privileges(true)
  puts privs.inspect  # => ["GET", "ADD", "MODIFY", "DELETE"]
end
```

### Complete Lifecycle Example

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Create a new user
  kadm5.create_principal('jdoe@EXAMPLE.COM', 'temp_password')

  # Look up the user
  princ = kadm5.get_principal('jdoe@EXAMPLE.COM')
  puts "Created: #{princ.principal}, kvno: #{princ.kvno}"

  # Reset their password
  kadm5.set_password('jdoe@EXAMPLE.COM', 'better_password')

  # Set password expiration to 90 days
  kadm5.set_pwexpire('jdoe@EXAMPLE.COM', (Time.now + 86400 * 90).to_i)

  # Generate random keys (e.g. for a service principal)
  kadm5.create_principal('HTTP/webapp.example.com@EXAMPLE.COM', 'temp')
  kadm5.generate_random_key('HTTP/webapp.example.com@EXAMPLE.COM')

  # Clean up
  kadm5.delete_principal('jdoe@EXAMPLE.COM')
  kadm5.delete_principal('HTTP/webapp.example.com@EXAMPLE.COM')
end
```

---

## Kerberos::Kadm5::Config

A read-only snapshot of the Kerberos admin configuration. The returned object is frozen.

### Reading Configuration

```ruby
config = Kerberos::Kadm5::Config.new

puts config.realm           # => "EXAMPLE.COM"
puts config.admin_server    # => "kdc.example.com"
puts config.kadmind_port    # => 749
puts config.kpasswd_port    # => 464
puts config.acl_file        # => "/var/kerberos/krb5kdc/kadm5.acl"
puts config.dict_file       # => nil (or path to dictionary file)
puts config.stash_file      # => "/var/kerberos/krb5kdc/.k5.EXAMPLE.COM"
puts config.mkey_name       # => "K/M"
puts config.enctype         # => 18 (AES-256)
puts config.max_life        # => 36000 (seconds)
puts config.max_rlife       # => 604800 (seconds)
puts config.expiration      # => Time object or nil
puts config.flags           # => Integer bitmask
puts config.kvno            # => 1
puts config.iprop_enabled   # => true or false
puts config.iprop_logfile   # => path or nil
puts config.iprop_poll_time # => Integer (seconds) or nil
puts config.iprop_port      # => Integer or nil
puts config.num_keysalts    # => Integer
puts config.keysalts        # => Array of KeySalt objects or nil

puts config.inspect
```

### Inspecting KeySalt Entries

```ruby
config = Kerberos::Kadm5::Config.new

if config.keysalts
  config.keysalts.each do |ks|
    puts "Enctype: #{ks.enctype}, Salttype: #{ks.salttype}"
  end
end
```

---

## Kerberos::Kadm5::Policy

Represents a Kerberos password policy. Policy objects are created in Ruby and then applied via the Kadm5 admin interface.

### Creating a Policy Object

```ruby
policy = Kerberos::Kadm5::Policy.new(
  name:        'strict',
  min_life:    3600,       # Minimum password lifetime: 1 hour
  max_life:    7776000,    # Maximum password lifetime: 90 days
  min_length:  12,         # Minimum password length
  min_classes: 3,          # Require at least 3 character classes
  history_num: 5           # Remember last 5 passwords
)

puts policy.name         # => "strict" (alias for policy.policy)
puts policy.policy       # => "strict"
puts policy.min_life     # => 3600
puts policy.max_life     # => 7776000
puts policy.min_length   # => 12
puts policy.min_classes  # => 3
puts policy.history_num  # => 5
```

### Creating a Policy in Kerberos

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Using a Policy object
  policy = Kerberos::Kadm5::Policy.new(name: 'standard', min_length: 8, min_classes: 2)
  kadm5.create_policy(policy)

  # Using a hash directly
  kadm5.create_policy(name: 'simple', min_length: 6)
end
```

### Retrieving a Policy

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Raises an exception if not found
  policy = kadm5.get_policy('standard')
  puts policy.inspect

  # Returns nil if not found
  policy = kadm5.find_policy('nonexistent')
  puts policy.nil?  # => true
end
```

### Modifying a Policy

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  policy = kadm5.get_policy('standard')
  policy.min_length = 10
  policy.min_classes = 3
  kadm5.modify_policy(policy)
end
```

### Listing Policies

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # List all policies
  kadm5.get_policies.each { |name| puts name }

  # List policies matching a pattern
  kadm5.get_policies('s*').each { |name| puts name }
end
```

### Deleting a Policy

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  kadm5.delete_policy('standard')
end
```

### Policy Lifecycle Example

```ruby
Kerberos::Kadm5.new(principal: 'admin/admin', password: 'admin_pass') do |kadm5|
  # Create a policy
  kadm5.create_policy(name: 'webusers', min_length: 10, min_classes: 2, max_life: 7776000)

  # Verify it was created
  policy = kadm5.get_policy('webusers')
  puts "Policy '#{policy.name}' created with min_length=#{policy.min_length}"

  # Modify it
  policy.min_length = 12
  kadm5.modify_policy(policy)

  # Clean up
  kadm5.delete_policy('webusers')
end
```

---

## Constants

### Encryption Type Constants

Available on `Kerberos::Krb5`:

| Constant | Value | Description |
|---|---|---|
| `ENCTYPE_NULL` | 0 | None |
| `ENCTYPE_DES_CBC_CRC` | 1 | DES cbc mode with CRC-32 |
| `ENCTYPE_DES_CBC_MD4` | 2 | DES cbc mode with RSA-MD4 |
| `ENCTYPE_DES_CBC_MD5` | 3 | DES cbc mode with RSA-MD5 |
| `ENCTYPE_DES_CBC_RAW` | 4 | DES cbc mode raw |
| `ENCTYPE_DES3_CBC_SHA` | 5 | DES-3 cbc mode with NIST-SHA |
| `ENCTYPE_DES3_CBC_RAW` | 6 | DES-3 cbc mode raw |
| `ENCTYPE_DES_HMAC_SHA1` | 8 | HMAC SHA1 |
| `ENCTYPE_DES3_CBC_SHA1` | 16 | DES3 CBC SHA1 |
| `ENCTYPE_AES128_CTS_HMAC_SHA1_96` | 17 | AES-128 CTS mode with 96-bit SHA-1 HMAC |
| `ENCTYPE_AES256_CTS_HMAC_SHA1_96` | 18 | AES-256 CTS mode with 96-bit SHA-1 HMAC |
| `ENCTYPE_ARCFOUR_HMAC` | 23 | ArcFour with HMAC/md5 |
| `ENCTYPE_ARCFOUR_HMAC_EXP` | 24 | ArcFour HMAC EXP |
| `ENCTYPE_UNKNOWN` | 511 | Unknown |

### Kadm5 Attribute Constants

Available on `Kerberos::Kadm5`:

| Constant | Description |
|---|---|
| `DISALLOW_POSTDATED` | Disallow postdated tickets |
| `DISALLOW_FORWARDABLE` | Disallow forwardable tickets |
| `DISALLOW_TGT_BASED` | Disallow TGT-based requests |
| `DISALLOW_RENEWABLE` | Disallow renewable tickets |
| `DISALLOW_PROXIABLE` | Disallow proxiable tickets |
| `DISALLOW_DUP_SKEY` | Disallow duplicate session keys |
| `DISALLOW_ALL_TIX` | Disallow all tickets |
| `REQUIRES_PRE_AUTH` | Require pre-authentication |
| `REQUIRES_HW_AUTH` | Require hardware authentication |
| `REQUIRES_PWCHANGE` | Require password change |
| `DISALLOW_SVR` | Disallow service tickets |
| `PWCHANGE_SERVICE` | Password change service |
| `SUPPORT_DESMD5` | Support DES-MD5 |
| `NEW_PRINC` | New principal |

---

## Error Handling

The library raises specific exception classes depending on the component:

```ruby
begin
  krb5 = Kerberos::Krb5.new
  krb5.get_init_creds_password('user@EXAMPLE.COM', 'wrong_password')
rescue Kerberos::Krb5::Exception => e
  puts "Krb5 error: #{e.message}"
ensure
  krb5&.close
end

begin
  Kerberos::Kadm5.new(principal: 'admin/admin', password: 'wrong') do |kadm5|
    # ...
  end
rescue Kerberos::Kadm5::Exception => e
  puts "Kadm5 error: #{e.message}"
end

# Principal not found (specific subclass)
begin
  Kerberos::Kadm5.new(principal: 'admin/admin', password: 'pass') do |kadm5|
    kadm5.get_principal('nonexistent@EXAMPLE.COM')
  end
rescue Kerberos::Kadm5::PrincipalNotFoundException => e
  puts "Principal not found: #{e.message}"
rescue Kerberos::Kadm5::Exception => e
  puts "Other admin error: #{e.message}"
end

# Keytab-specific errors
begin
  keytab = Kerberos::Krb5::Keytab.new('FILE:/nonexistent/path')
rescue Kerberos::Krb5::Keytab::Exception => e
  puts "Keytab error: #{e.message}"
end
```

### Exception Hierarchy

```
StandardError
├── Kerberos::Krb5::Exception
│   └── (general Kerberos errors)
├── Kerberos::Krb5::Keytab::Exception
│   └── (keytab-specific errors)
├── Kerberos::Kadm5::Exception
│   └── (admin errors)
└── Kerberos::Kadm5::PrincipalNotFoundException
    └── (principal lookup failures)
```
