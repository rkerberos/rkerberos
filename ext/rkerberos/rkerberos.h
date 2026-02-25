
#ifndef KRB5_AUTH_H_INCLUDED
#define KRB5_AUTH_H_INCLUDED

#include <ruby.h>
#include <krb5.h>
#include <string.h>

// Make the context data type visible to other C files
extern const rb_data_type_t rkrb5_context_data_type;
// Make the config data type visible to other C files
extern const rb_data_type_t rkadm5_config_data_type;

#ifdef __cplusplus
extern "C" {
#endif
#ifdef HAVE_KADM5_ADMIN_H
#include <kadm5/admin.h>
#endif

// Make the ccache data type visible to other C files
extern const rb_data_type_t rkrb5_ccache_data_type;
// Make the keytab data type visible to other C files
extern const rb_data_type_t rkrb5_keytab_data_type;

#ifdef __cplusplus
}
#endif

#ifdef HAVE_KADM5_ADMIN_H
// Make the policy data type visible to other C files
extern const rb_data_type_t rkadm5_policy_data_type;
#endif

// Function Prototypes
void Init_context();
#ifdef HAVE_KADM5_ADMIN_H
void Init_kadm5();
void Init_config();
void Init_policy();
#endif
void Init_principal();
void Init_keytab();
void Init_keytab_entry();
void Init_ccache();

// Defined in rkerberos.c
VALUE rb_hash_aref2(VALUE, VALUE);

// Variable declarations
extern VALUE mKerberos;
extern VALUE cKrb5;
extern VALUE cKrb5CCache;
extern VALUE cKrb5Context;
extern VALUE cKrb5Keytab;
extern VALUE cKrb5KtEntry;
extern VALUE cKrb5Exception;
extern VALUE cKrb5Principal;
extern VALUE cKadm5;
extern VALUE cKadm5Config;
extern VALUE cKadm5Exception;
extern VALUE cKadm5Policy;

// Kerberos::Krb5
typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_principal princ;
  krb5_keytab keytab;
} RUBY_KRB5;

// Kerberos::Context
typedef struct {
  krb5_context ctx;
  krb5_enctype etypes;
} RUBY_KRB5_CONTEXT;

// Kerberos::Kadm5
typedef struct {
  krb5_context ctx;
  krb5_principal princ;
  void* handle;
  char** db_args;
} RUBY_KADM5;

// Kerberos::Krb5::Keytab::Entry
typedef struct {
  krb5_principal principal;
  krb5_timestamp timestamp;
  krb5_kvno vno;
  krb5_keyblock key;
} RUBY_KRB5_KT_ENTRY;

// Kerberos::Krb5::Keytab
typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_keytab keytab;
} RUBY_KRB5_KEYTAB;

typedef struct {
  krb5_context ctx;
  krb5_principal principal;
} RUBY_KRB5_PRINC;

typedef struct {
  krb5_context ctx;
  krb5_ccache ccache;
  krb5_principal principal;
} RUBY_KRB5_CCACHE;

#ifdef HAVE_KADM5_ADMIN_H
typedef struct {
  krb5_context ctx;
  kadm5_config_params config;
} RUBY_KADM5_CONFIG;

typedef struct {
  krb5_context ctx;
  kadm5_policy_ent_rec policy;
} RUBY_KADM5_POLICY;
#endif
#endif
