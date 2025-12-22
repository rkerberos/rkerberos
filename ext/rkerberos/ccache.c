#include <rkerberos.h>

VALUE cKrb5CCache;

// Free function for the Kerberos::Krb5::CCache class.
static void rkrb5_ccache_free(RUBY_KRB5_CCACHE* ptr){
  if(!ptr)
    return;

  if(ptr->ccache)
    krb5_cc_close(ptr->ctx, ptr->ccache);

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

const rb_data_type_t krb5_ccache_type = {
  .wrap_struct_name = "krb5_ccache",
  .function = {
    .dfree = (void (*)(void*))rkrb5_ccache_free,
    .dsize = NULL,
    .dmark = NULL,
  },
  .data = NULL,
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::CCache class.
static VALUE rkrb5_ccache_allocate(VALUE klass){
  RUBY_KRB5_CCACHE* ptr = malloc(sizeof(RUBY_KRB5_CCACHE));
  memset(ptr, 0, sizeof(RUBY_KRB5_CCACHE));
  return TypedData_Wrap_Struct(klass, &krb5_ccache_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::CredentialsCache.new(principal = nil, cache_name = nil)
 *
 * Creates and returns a new Kerberos::CredentialsCache object. If cache_name
 * is specified, then that cache is used, which must be in "type:residual"
 * format, where 'type' is a type known to Kerberos (typically 'FILE').
 *
 * If a +principal+ is specified, then it creates or refreshes the credentials
 * cache with the primary principal set to +principal+. If the credentials
 * cache already exists, its contents are destroyed.
 *
 * Note that the principal's credentials are not set via the constructor.
 * It merely creates the cache and sets the default principal.
 */
static VALUE rkrb5_ccache_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;
  VALUE v_principal, v_name;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &krb5_ccache_type, ptr);

  rb_scan_args(argc, argv, "02", &v_principal, &v_name);

  // Convert the principal name to a principal object
  if(RTEST(v_principal)){
    Check_Type(v_principal, T_STRING);

    kerror = krb5_parse_name(
      ptr->ctx,
      StringValueCStr(v_principal),
      &ptr->principal
    );

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));
  }

  // Initialize the context
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Set the credentials cache using the default cache if no name is provided
  if(NIL_P(v_name)){
    kerror = krb5_cc_default(ptr->ctx, &ptr->ccache);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(kerror));
  }
  else{
    Check_Type(v_name, T_STRING);
    kerror = krb5_cc_resolve(ptr->ctx, StringValueCStr(v_name), &ptr->ccache);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_cc_resolve: %s", error_message(kerror));
  }

  // Initialize the credentials cache if a principal was provided
  if(RTEST(v_principal)){
    kerror = krb5_cc_initialize(ptr->ctx, ptr->ccache, ptr->principal);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_cc_initialize: %s", error_message(kerror));
  }

  return self;
}

/*
 * call-seq:
 *   ccache.close
 *
 * Closes the ccache object. Once the ccache object is closed no more
 * methods may be called on it, or an exception will be raised.
 *
 * Note that unlike ccache.destroy, this does not delete the cache.
 */
static VALUE rkrb5_ccache_close(VALUE self){
  RUBY_KRB5_CCACHE* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &krb5_ccache_type, ptr);

  if(!ptr->ctx)
    return self;

  if(ptr->ccache)
    krb5_cc_close(ptr->ctx, ptr->ccache);

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;

  return self;
}

/*
 * call-seq:
 *   ccache.default_name
 *
 * Returns the name of the default credentials cache.
 *
 * This is typically a file under /tmp with a name like 'krb5cc_xxxx',
 * where 'xxxx' is the uid of the current process owner.
 */
static VALUE rkrb5_ccache_default_name(VALUE self){
  RUBY_KRB5_CCACHE* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &krb5_ccache_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  return rb_str_new2(krb5_cc_default_name(ptr->ctx));
}

/*
 * call-seq:
 *   ccache.primary_principal
 *
 * Returns the name of the primary principal of the credentials cache.
 */
static VALUE rkrb5_ccache_primary_principal(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;
  char* name;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &krb5_ccache_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_cc_get_principal(ptr->ctx, ptr->ccache, &ptr->principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_get_principal: %s", error_message(kerror));

  kerror = krb5_unparse_name(ptr->ctx, ptr->principal, &name);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_unparse_name: %s", error_message(kerror));

  return rb_str_new2(name);
}

/*
 * call-seq:
 *   ccache.destroy
 *
 * Destroy the credentials cache of the current principal. This also closes
 * the object and it cannot be reused.
 *
 * If the cache was destroyed then true is returned. If there is no cache
 * then false is returned.
 */
static VALUE rkrb5_ccache_destroy(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;
  VALUE v_bool = Qtrue;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &krb5_ccache_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_cc_destroy(ptr->ctx, ptr->ccache);

  // Don't raise an error if there's no cache. Just return false.
  if(kerror){
    if((kerror == KRB5_CC_NOTFOUND) || (kerror == KRB5_FCC_NOFILE)){
      v_bool = Qfalse;
    }
    else{
      if(ptr->principal)
        krb5_free_principal(ptr->ctx, ptr->principal);

      if(ptr->ctx)
        krb5_free_context(ptr->ctx);

      rb_raise(cKrb5Exception, "krb5_cc_destroy: %s", error_message(kerror));
    }
  }

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;

  return v_bool;
}

void Init_ccache(){
  /* The Kerberos::Krb5::CredentialsCache class encapsulates a Kerberos credentials cache. */
  cKrb5CCache = rb_define_class_under(cKrb5, "CredentialsCache", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5CCache, rkrb5_ccache_allocate);

  // Constructor
  rb_define_method(cKrb5CCache, "initialize", rkrb5_ccache_initialize, -1);

  // Instance Methods
  rb_define_method(cKrb5CCache, "close", rkrb5_ccache_close, 0);
  rb_define_method(cKrb5CCache, "default_name", rkrb5_ccache_default_name, 0);
  rb_define_method(cKrb5CCache, "destroy", rkrb5_ccache_destroy, 0);
  rb_define_method(cKrb5CCache, "primary_principal", rkrb5_ccache_primary_principal, 0);

  // Aliases
  rb_define_alias(cKrb5CCache, "delete", "destroy");
}
