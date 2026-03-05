#include <rkerberos.h>

VALUE cKrb5CCache;


// TypedData functions for RUBY_KRB5_CCACHE
static void rkrb5_ccache_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_CCACHE *c = (RUBY_KRB5_CCACHE *)ptr;
  if (c->ccache)
    krb5_cc_close(c->ctx, c->ccache);
  if (c->principal)
    krb5_free_principal(c->ctx, c->principal);
  if (c->ctx)
    krb5_free_context(c->ctx);
  free(c);
}

static size_t rkrb5_ccache_typed_size(const void *ptr) {
  return sizeof(RUBY_KRB5_CCACHE);
}

const rb_data_type_t rkrb5_ccache_data_type = {
  "RUBY_KRB5_CCACHE",
  {NULL, rkrb5_ccache_typed_free, rkrb5_ccache_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::CCache class.
static VALUE rkrb5_ccache_allocate(VALUE klass){
  RUBY_KRB5_CCACHE* ptr = ALLOC(RUBY_KRB5_CCACHE);
  memset(ptr, 0, sizeof(RUBY_KRB5_CCACHE));
  return TypedData_Wrap_Struct(klass, &rkrb5_ccache_data_type, ptr);
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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  rb_scan_args(argc, argv, "02", &v_principal, &v_name);

  if(RTEST(v_principal))
    Check_Type(v_principal, T_STRING);

  // Initialize the context
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Convert the principal name to a principal object
  if(RTEST(v_principal)){
    kerror = krb5_parse_name(
      ptr->ctx,
      StringValueCStr(v_principal),
      &ptr->principal
    );

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));
  }

  // Set the credentials cache using the default cache if no name is provided
  if(NIL_P(v_name)){
    kerror = krb5_cc_default(ptr->ctx, &ptr->ccache);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(kerror));
  }
  else {
    /* No principal and no explicit cache name => do not open a cache */
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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  return rb_str_new2(krb5_cc_default_name(ptr->ctx));
}

// Wrapper for krb5_cc_get_name; returns the actual ccache name.
static VALUE rkrb5_ccache_get_name(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  const char *name;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  name = krb5_cc_get_name(ptr->ctx, ptr->ccache);
  if(!name)
    rb_raise(cKrb5Exception, "krb5_cc_get_name returned NULL");

  return rb_str_new2(name);
}

// Wrapper for krb5_cc_get_type; returns the cache type string.
static VALUE rkrb5_ccache_get_type(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  const char *type;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  type = krb5_cc_get_type(ptr->ctx, ptr->ccache);
  if(!type)
    rb_raise(cKrb5Exception, "krb5_cc_get_type returned NULL");

  return rb_str_new2(type);
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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  if(ptr->principal){
    krb5_free_principal(ptr->ctx, ptr->principal);
    ptr->principal = NULL;
  }

  kerror = krb5_cc_get_principal(ptr->ctx, ptr->ccache, &ptr->principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_get_principal: %s", error_message(kerror));

  kerror = krb5_unparse_name(ptr->ctx, ptr->principal, &name);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_unparse_name: %s", error_message(kerror));

  VALUE v_name = rb_str_new2(name);
  krb5_free_unparsed_name(ptr->ctx, name);

  return v_name;
}

// Simple wrapper around krb5_cc_get_principal returning a principal name string.
static VALUE rkrb5_ccache_principal(VALUE self){
  return rkrb5_ccache_primary_principal(self);
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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  /* If there's no cache opened for this object return false as the
     caller expects (no-op). This avoids passing NULL into krb5_cc_destroy. */
  if (!ptr->ccache)
    return Qfalse;

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

      ptr->ccache = NULL;
      ptr->ctx = NULL;
      ptr->principal = NULL;

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

// Duplicate the credentials cache object.
// call-seq:
//   ccache.dup -> new_ccache
//
// Returns a new Kerberos::Krb5::CredentialsCache that references the
// same underlying cache data. The new object has its own krb5 context so
// that closing one cache does not affect the other.
static VALUE rkrb5_ccache_dup(VALUE self){
  RUBY_KRB5_CCACHE *ptr, *newptr;
  krb5_error_code kerror;
  VALUE newobj;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  // allocate new ruby object and struct
  newobj = rkrb5_ccache_allocate(CLASS_OF(self));
  TypedData_Get_Struct(newobj, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, newptr);

  // initialize a fresh context for the duplicate
  kerror = krb5_init_context(&newptr->ctx);
  if(kerror){
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));
  }

  // perform ccache duplication using the new context
  kerror = krb5_cc_dup(newptr->ctx, ptr->ccache, &newptr->ccache);
  if(kerror){
    krb5_free_context(newptr->ctx);
    newptr->ctx = NULL;
    rb_raise(cKrb5Exception, "krb5_cc_dup: %s", error_message(kerror));
  }

  // principal is not copied; let callers query primary_principal on each
  newptr->principal = NULL;

  return newobj;
}

void Init_ccache(void){
  /* The Kerberos::Krb5::CredentialsCache class encapsulates a Kerberos credentials cache. */
  cKrb5CCache = rb_define_class_under(cKrb5, "CredentialsCache", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5CCache, rkrb5_ccache_allocate);

  // Constructor
  rb_define_method(cKrb5CCache, "initialize", rkrb5_ccache_initialize, -1);

  // Instance Methods
  rb_define_method(cKrb5CCache, "close", rkrb5_ccache_close, 0);
  rb_define_method(cKrb5CCache, "default_name", rkrb5_ccache_default_name, 0);
  rb_define_method(cKrb5CCache, "cache_name", rkrb5_ccache_get_name, 0);
  rb_define_method(cKrb5CCache, "cache_type", rkrb5_ccache_get_type, 0);
  rb_define_method(cKrb5CCache, "destroy", rkrb5_ccache_destroy, 0);
  rb_define_method(cKrb5CCache, "primary_principal", rkrb5_ccache_primary_principal, 0);
  rb_define_method(cKrb5CCache, "principal", rkrb5_ccache_principal, 0);
  rb_define_method(cKrb5CCache, "dup", rkrb5_ccache_dup, 0);
  rb_define_alias(cKrb5CCache, "clone", "dup");

  // Aliases
  rb_define_alias(cKrb5CCache, "delete", "destroy");
}
