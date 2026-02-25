# Dockerfile for rkerberos Ruby gem testing
# allow the base Ruby version to be overridden via build argument
ARG RUBY=3.4
FROM ruby:${RUBY}

# Install MIT Kerberos, KDC, admin server, and build tools
RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            libkrb5-dev krb5-user krb5-kdc krb5-admin-server rake build-essential && \
        rm -rf /var/lib/apt/lists/*

# Set up a working directory
WORKDIR /app

# Set admin credentials for tests (matches docker-compose.yml)
ENV KRB5_ADMIN_PRINCIPAL=admin/admin@EXAMPLE.COM
ENV KRB5_ADMIN_PASSWORD=adminpassword

# Copy the gemspec and Gemfile for dependency installation
COPY Gemfile rkerberos.gemspec ./


# Install gem dependencies and RSpec
RUN bundle install && gem install rspec


# Create a more complete krb5.conf for testing (with kadmin support)
RUN echo "[libdefaults]\n  default_realm = EXAMPLE.COM\n  dns_lookup_realm = false\n  dns_lookup_kdc = false\n  ticket_lifetime = 24h\n  renew_lifetime = 7d\n  forwardable = true\n[realms]\n  EXAMPLE.COM = {\n    kdc = kerberos-kdc\n    admin_server = kerberos-kdc\n    default_domain = example.com\n  }\n[domain_realm]\n  .example.com = EXAMPLE.COM\n  example.com = EXAMPLE.COM\n[kadmin]\n  default_keys = des-cbc-crc:normal des-cbc-md5:normal aes256-cts:normal aes128-cts:normal rc4-hmac:normal\n  admin_server = kerberos-kdc\n" > /etc/krb5.conf


# Create a minimal KDC and admin server config, and a permissive ACL for kadmin
RUN mkdir -p /etc/krb5kdc && \
    echo "[kdcdefaults]\n kdc_ports = 88\n[kdc]\n profile = /etc/krb5.conf\n" > /etc/krb5kdc/kdc.conf && \
    echo "admin/admin@EXAMPLE.COM *" > /etc/krb5kdc/kadm5.acl


# Copy the rest of the code
COPY . .

# Compile the C extension
RUN rake compile

# Run RSpec tests
CMD ["bundle", "exec", "rspec"]
