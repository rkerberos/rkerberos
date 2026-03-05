#include <rkerberos.h>

#ifdef HAVE_PROFILE_H
#include <profile.h>
#endif

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
 *   Kerberos::Context.new(options = {})
 *
 * Creates and returns a new Kerberos::Context object.
 *
 * The options hash may be one or both of the following keys:
 *
 *   :secure  => true|false           # Use config files only, ignore env variables
 *   :profile => '/path/to/krb5.conf' # Use the specified profile file
 */
static VALUE rkrb5_context_initialize(int argc, VALUE *argv, VALUE self){
  RUBY_KRB5_CONTEXT* ptr;
  VALUE v_opts;
  VALUE v_secure, v_profile;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ptr);

  rb_scan_args(argc, argv, "01", &v_opts);

  // Default behavior is a normal context that may respect environment.
  if (NIL_P(v_opts)) {
    kerror = krb5_init_context(&ptr->ctx);
    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

    return self;
  }

  Check_Type(v_opts, T_HASH);

  v_secure = rb_hash_aref2(v_opts, ID2SYM(rb_intern("secure")));
  v_profile = rb_hash_aref2(v_opts, ID2SYM(rb_intern("profile")));

#ifdef HAVE_PROFILE_INIT_PATH
  /*
   * If a profile path is supplied, load it via profile_init_path() and
   * create a context from that profile. The KRB5_INIT_CONTEXT_SECURE flag
   * is used when the :secure option is truthy.
   */
  if (!NIL_P(v_profile)){
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
  }
#endif

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

void Init_context(void){
  /* The Kerberos::Krb5::Context class encapsulates a Kerberos context. */
  cKrb5Context = rb_define_class_under(cKrb5, "Context", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5Context, rkrb5_context_allocate);

  // Constructor
  rb_define_method(cKrb5Context, "initialize", rkrb5_context_initialize, -1);

  // Instance Methods
  rb_define_method(cKrb5Context, "close", rkrb5_context_close, 0);
}
