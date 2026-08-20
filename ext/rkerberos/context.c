#include <rkerberos.h>

#include <profile.h>

VALUE cKrb5Context;

// Free function for the Kerberos::Krb5::Context class.

// TypedData functions for RUBY_KRB5_CONTEXT
static void rkrb5_context_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_CONTEXT *c = (RUBY_KRB5_CONTEXT *)ptr;
  if (c->ctx)
    krb5_free_context(c->ctx);
  free(c);
}

static size_t rkrb5_context_typed_size(const void *ptr) {
  return sizeof(RUBY_KRB5_CONTEXT);
}

const rb_data_type_t rkrb5_context_data_type = {
  "RUBY_KRB5_CONTEXT",
  {NULL, rkrb5_context_typed_free, rkrb5_context_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::Context class.
static VALUE rkrb5_context_allocate(VALUE klass){
  RUBY_KRB5_CONTEXT* ptr = ALLOC(RUBY_KRB5_CONTEXT);
  memset(ptr, 0, sizeof(RUBY_KRB5_CONTEXT));
  return TypedData_Wrap_Struct(klass, &rkrb5_context_data_type, ptr);
}

/*
 * call-seq:
 *   context.close
 *
 * Closes the context object.
 */
static VALUE rkrb5_context_close(VALUE self){
  RUBY_KRB5_CONTEXT* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ptr);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;

  return self;
}

/*
 * call-seq:
 *   Kerberos::Krb5::Context.new(secure: false, profile: nil)
 *
 * Creates and returns a new Kerberos::Context object.
 *
 * The following keyword arguments are supported:
 *
 *   :secure  => true|false           # Use config files only, ignore env variables
 *   :profile => '/path/to/krb5.conf' # Use the specified profile file
 *
 * Note that the profile option may not be supported on your platform.
 */
static VALUE rkrb5_context_initialize(int argc, VALUE *argv, VALUE self){
  RUBY_KRB5_CONTEXT* ptr;
  VALUE v_opts;
  VALUE v_secure, v_profile;
  ID kw_table[2] = { rb_intern("secure"), rb_intern("profile") };
  VALUE kw_vals[2];
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_opts);

  // Default behavior is a normal context that may respect environment.
  if (NIL_P(v_opts)) {
    kerror = krb5_init_context(&ptr->ctx);
    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

    return self;
  }

  rb_get_kwargs(v_opts, kw_table, 0, 2, kw_vals);
  v_secure = kw_vals[0] == Qundef ? Qfalse : kw_vals[0];
  v_profile = kw_vals[1] == Qundef ? Qnil : kw_vals[1];

  /*
   * If a profile path is supplied, load it via profile_init_path() and
   * create a context from that profile. The KRB5_INIT_CONTEXT_SECURE flag
   * is used when the :secure option is truthy.
   */
  if (!NIL_P(v_profile)){
#ifndef HAVE_PROFILE_INIT_PATH
    rb_raise(rb_eArgError, "profile option not supported on this platform");
#else
    Check_Type(v_profile, T_STRING);

    const char *profile_path = StringValueCStr(v_profile);
    profile_t profile = NULL;
    long pres = profile_init_path(profile_path, &profile);

    if(pres != 0)
      rb_raise(cKrb5Exception, "profile_init_path: %ld", pres);

    krb5_flags flags = RTEST(v_secure) ? KRB5_INIT_CONTEXT_SECURE : 0;
    kerror = krb5_init_context_profile(profile, flags, &ptr->ctx);

    profile_release(profile);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context_profile: %s", error_message(kerror));

    return self;
#endif
  }

  // No profile given, choose secure or normal init.
  if (RTEST(v_secure)){
    kerror = krb5_init_secure_context(&ptr->ctx);
    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_secure_context: %s", error_message(kerror));
  }
  else{
    kerror = krb5_init_context(&ptr->ctx);
    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));
  }

  return self;
}

/*
 * call-seq:
 *   context.default_realm -> String
 *
 * Returns the default realm from this context.
 */
static VALUE rkrb5_context_default_realm(VALUE self){
  RUBY_KRB5_CONTEXT* ptr;
  char* realm;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_get_default_realm(ptr->ctx, &realm);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_get_default_realm: %s", error_message(kerror));

  VALUE v_realm = rb_str_new2(realm);
  krb5_free_default_realm(ptr->ctx, realm);

  return v_realm;
}

/*
 * call-seq:
 *   context.default_realm = realm
 *
 * Sets the default realm for this context. If +realm+ is nil the default
 * from krb5.conf is restored.
 */
static VALUE rkrb5_context_set_default_realm(VALUE self, VALUE v_realm){
  RUBY_KRB5_CONTEXT* ptr;
  char* realm;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  if(NIL_P(v_realm)){
    realm = NULL;
  }
  else{
    Check_Type(v_realm, T_STRING);
    realm = StringValueCStr(v_realm);
  }

  kerror = krb5_set_default_realm(ptr->ctx, realm);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_set_default_realm: %s", error_message(kerror));

  return v_realm;
}

void Init_context(void){
  /* The Kerberos::Krb5::Context class encapsulates a Kerberos context. */
  cKrb5Context = rb_define_class_under(cKrb5, "Context", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5Context, rkrb5_context_allocate);

  // Constructor
  rb_define_method(cKrb5Context, "initialize", rkrb5_context_initialize, -1);

  // Instance Methods
  rb_define_method(cKrb5Context, "close", rkrb5_context_close, 0);
  rb_define_method(cKrb5Context, "default_realm", rkrb5_context_default_realm, 0);
  rb_define_method(cKrb5Context, "default_realm=", rkrb5_context_set_default_realm, 1);
}
