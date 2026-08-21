[![Ruby](https://github.com/rkerberos/rkerberos/actions/workflows/ci.yml/badge.svg)](https://github.com/rkerberos/rkerberos/actions/workflows/ci.yml)

# Description
The rkerberos library provides a Ruby interface for Kerberos.

## Code synopsis

Some basic usage:

```ruby
require 'rkerberos'

# Client
krb = Kerberos::Krb5.new
puts krb.default_realm
puts krb.default_principal
puts krb.get_permitted_enctypes.keys.join(',')

# Credentials cache
cc = Kerberos::Krb5::CredentialsCache.new
krb.get_init_creds_password(
  principal: ENV['KRB5_PRINCIPAL'],
  password: ENV['KRB5_PASSWORD'],
  ccache: cc
)
krb.verify_init_creds
puts cc.primary_principal

# Keytab
kt_name = Kerberos::Krb5::Keytab.new.default_name # e.g. "FILE:/etc/krb5.keytab"
krb.get_init_creds_keytab(principal: 'host/server.example.com', keytab: kt_name)
krb.get_init_creds_keytab(principal: 'host/server.example.com', keytab: kt_name, ccache: cc) # or write to cache

# Admin
Kerberos::Kadm5.new(principal: ENV['KRB5_ADMIN_PRINCIPAL'], password: ENV['KRB5_ADMIN_PASSWORD']) do |kadmin|
  kadmin.create_principal(name: 'newuser@EXAMPLE.COM', password: 'initialpass')
  kadmin.set_password('newuser@EXAMPLE.COM', 'betterpass')
  kadmin.delete_principal('newuser@EXAMPLE.COM')
end

# Contexts
ctx = Kerberos::Krb5::Context.new # standard context
ctx = Kerberos::Krb5::Context.new(profile: '/etc/krb5.conf') # or use a profile
ctx = Kerberos::Krb5::Context.new(secure: true) # or use a secure context
ctx.close
```

# Requirements

# Linux
   Install krb5 development libraries using your package manager. For example:

      # Debian/Ubuntu
      sudo apt-get install libkrb5-dev

      # Fedora/RHEL
      sudo dnf install krb5-devel

   Then install this gem:

      gem install rkerberos

   or if using bundler:

      bundle install

  Kerberos 1.7.0 or later, including admin header and library files.

# OS X
  Install krb5 using homebrew:

    `brew install krb5`

  then install this gem using the homebrew version of krb5:

    # Or '/opt/homebrew/opt/krb' depending on your system
    `gem install rkerberos -- --with-rkerberos-dir=/usr/local/opt/krb5`

  or if using bundler:

    `bundle config --global build.rkerberos --with-rkerberos-dir=/usr/local/opt/krb5`
    `bundle install`

# Testing

## Prerequisites
- Ruby 3.2 or later
- Docker or Podman
- docker-compose or podman-compose

## Running Tests with Docker
1. Start the Kerberos and LDAP services:
   ```bash
   docker-compose up -d
   ```

2. Run the test suite:
   ```bash
   docker-compose run --rm rkerberos-test bundle exec rspec
   ```

3. Stop the services when done:
   ```bash
   docker-compose down
   ```

   Add the `--remove-orphans` switch if it's being a pain.

## Running Tests with Podman
1. Start the Kerberos and LDAP services:
   ```bash
   podman-compose up -d
   ```

2. Run the test suite:
   ```bash
   podman-compose run --rm rkerberos-test
   ```

3. Stop the services when done:
   ```bash
   podman-compose down
   ```

## Local Development
If you make changes to the Ruby code or C extensions:

1. Rebuild the test container:
   ```bash
   podman-compose build --no-cache rkerberos-test
   ```

2. Run the tests again:
   ```bash
   podman-compose run --rm rkerberos-test
   ```

Alternatively, you can just run containerized tests via the `spec:compose`
Rake task. This task runs the same containerized workflow used above and
prefers `podman-compose` with a `docker-compose` fallback.

```bash
# build image and run RSpec inside the test container
rake spec:compose
# skip the build step by passing a positional or named argument:
# (equivalent forms)
rake spec:compose[true]
rake "spec:compose[fast=true]"
```

The test environment includes:
- MIT Kerberos KDC (Key Distribution Center)
- OpenLDAP server for directory services
- Pre-configured test principals and keytabs

# Notes
  The rkerberos library is a repackaging of my custom branch of the krb5_auth
  library. Eventually the gem djberg96-krb5_auth will be removed from the gem
  index.

# MIT vs Heimdal
  This code was written for the MIT Kerberos library. It has not been tested
  with the Heimdal Kerberos library.

# TODO
* Create a separate class for the replay cache.
* Better credentials cache support.

# Authors
* Daniel Berger
* Dominic Cleal
* Simon Levermann

# License
  rkerberos is distributed under the Artistic-2.0 license.
