#include <rkerberos.h>

VALUE cKrb5CCache;


// TypedData functions for RUBY_KRB5_CCACHE
static void rkrb5_ccache_typed_mark(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_CCACHE *c = (RUBY_KRB5_CCACHE *)ptr;
  if (c->rb_context != Qnil)
    rb_gc_mark(c->rb_context);
}

static void rkrb5_ccache_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_CCACHE *c = (RUBY_KRB5_CCACHE *)ptr;
  if (c->ccache)
    krb5_cc_close(c->ctx, c->ccache);
  if (c->principal)
    krb5_free_principal(c->ctx, c->principal);
  if (c->ctx && c->rb_context == Qnil)
    krb5_free_context(c->ctx);
  free(c);
}

static size_t rkrb5_ccache_typed_size(const void *ptr) {
  return sizeof(RUBY_KRB5_CCACHE);
}

const rb_data_type_t rkrb5_ccache_data_type = {
  "RUBY_KRB5_CCACHE",
  {rkrb5_ccache_typed_mark, rkrb5_ccache_typed_free, rkrb5_ccache_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::CCache class.
static VALUE rkrb5_ccache_allocate(VALUE klass){
  RUBY_KRB5_CCACHE* ptr = ALLOC(RUBY_KRB5_CCACHE);
  memset(ptr, 0, sizeof(RUBY_KRB5_CCACHE));
  ptr->rb_context = Qnil;
  return TypedData_Wrap_Struct(klass, &rkrb5_ccache_data_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::CredentialsCache.new(principal: nil, cache_name: nil, context: nil)
 *
 * Creates and returns a new Kerberos::CredentialsCache object. Accepts the
 * following keyword arguments:
 *
 * - +principal+: A string principal name. If specified, the credentials cache
 *   is created or refreshed with this as the primary principal. If a cache
 *   already exists, its contents are destroyed. May also be an object that
 *   responds to the `.principal` method.
 *
 * - +cache_name+: The name of the credentials cache to use, which must be in
 *   "type:residual" format, where 'type' is a type known to Kerberos
 *   (typically 'FILE'). If omitted, the default cache is used.
 *
 * - +context+: A Kerberos::Krb5::Context object. If provided, that context is
 *   used instead of creating a new one via krb5_init_context.
 *
 * Note that the principal's credentials are not set via the constructor.
 * It merely creates the cache and sets the default principal.
 */
static VALUE rkrb5_ccache_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;
  VALUE v_opts, v_principal, v_name, v_context;
  ID kw_table[3] = { rb_intern("principal"), rb_intern("cache_name"), rb_intern("context") };
  VALUE kw_vals[3];

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    v_opts = rb_hash_new();

  rb_get_kwargs(v_opts, kw_table, 0, 3, kw_vals);
  v_principal = kw_vals[0] == Qundef ? Qnil : kw_vals[0];
  v_name = kw_vals[1] == Qundef ? Qnil : kw_vals[1];
  v_context = kw_vals[2] == Qundef ? Qnil : kw_vals[2];

  if(!NIL_P(v_principal)){
    if(rb_respond_to(v_principal, rb_intern("principal")))
      v_principal = rb_funcall(v_principal, rb_intern("principal"), 0);

    Check_Type(v_principal, T_STRING);
  }

  // Initialize or borrow the context
  if(!NIL_P(v_context)){
    RUBY_KRB5_CONTEXT* ctx_ptr;

    if(!rb_obj_is_kind_of(v_context, cKrb5Context))
      rb_raise(rb_eTypeError, "context must be a Kerberos::Krb5::Context object");

    TypedData_Get_Struct(v_context, RUBY_KRB5_CONTEXT, &rkrb5_context_data_type, ctx_ptr);

    if(!ctx_ptr->ctx)
      rb_raise(cKrb5Exception, "context is closed");

    ptr->ctx = ctx_ptr->ctx;
    ptr->rb_context = v_context;
  }
  else{
    kerror = krb5_init_context(&ptr->ctx);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

    ptr->rb_context = Qnil;
  }

  // Convert the principal name to a principal object
  if(!NIL_P(v_principal)){
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

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    return self;

  if(ptr->ccache)
    krb5_cc_close(ptr->ctx, ptr->ccache);

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx && ptr->rb_context == Qnil)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;
  ptr->rb_context = Qnil;

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

  kerror = krb5_cc_destroy(ptr->ctx, ptr->ccache);

  // Don't raise an error if there's no cache. Just return false.
  if(kerror){
    if((kerror == KRB5_CC_NOTFOUND) || (kerror == KRB5_FCC_NOFILE)){
      v_bool = Qfalse;
    }
    else{
      if(ptr->principal)
        krb5_free_principal(ptr->ctx, ptr->principal);

      if(ptr->ctx && ptr->rb_context == Qnil)
        krb5_free_context(ptr->ctx);

      ptr->ccache = NULL;
      ptr->ctx = NULL;
      ptr->principal = NULL;
      ptr->rb_context = Qnil;

      rb_raise(cKrb5Exception, "krb5_cc_destroy: %s", error_message(kerror));
    }
  }

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx && ptr->rb_context == Qnil)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;
  ptr->rb_context = Qnil;

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

/*
 * call-seq:
 *   ccache.full_name -> String
 *
 * Returns the full name of the credential cache, including the type prefix,
 * e.g. "FILE:/tmp/krb5cc_1000".
 */
static VALUE rkrb5_ccache_full_name(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  char *full_name;
  krb5_error_code kerror;
  VALUE result;

  TypedData_Get_Struct(self, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_cc_get_full_name(ptr->ctx, ptr->ccache, &full_name);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_get_full_name: %s", error_message(kerror));

  result = rb_str_new2(full_name);
  krb5_free_string(ptr->ctx, full_name);

  return result;
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
  rb_define_method(cKrb5CCache, "full_name", rkrb5_ccache_full_name, 0);
  rb_define_method(cKrb5CCache, "dup", rkrb5_ccache_dup, 0);
  rb_define_alias(cKrb5CCache, "clone", "dup");

  // Aliases
  rb_define_alias(cKrb5CCache, "delete", "destroy");
  rb_define_alias(cKrb5CCache, "principal", "primary_principal");
}
