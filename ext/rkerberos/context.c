#include <rkerberos.h>

VALUE cKrb5Context;

// Free function for the Kerberos::Krb5::Context class.
static void rkrb5_context_free(RUBY_KRB5_CONTEXT* ptr){
  if(!ptr)
    return;

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

const rb_data_type_t krb5_context_type = {
  .wrap_struct_name = "krb5_context",
  .function = {
    .dfree = (void (*)(void*))rkrb5_context_free,
    .dsize = NULL,
    .dmark = NULL,
  },
  .data = NULL,
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::Context class.
static VALUE rkrb5_context_allocate(VALUE klass){
  RUBY_KRB5_CONTEXT* ptr = malloc(sizeof(RUBY_KRB5_CONTEXT));
  memset(ptr, 0, sizeof(RUBY_KRB5_CONTEXT));
  return TypedData_Wrap_Struct(klass, &krb5_context_type, ptr);
}

/*
 * call-seq:
 *   context.close
 *
 * Closes the context object.
 */
static VALUE rkrb5_context_close(VALUE self){
  RUBY_KRB5_CONTEXT* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &krb5_context_type, ptr);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;

  return self;
}

/*
 * call-seq:
 *   Kerberos::Context.new
 *
 * Creates and returns a new Kerberos::Context object.
 *
 * This class is not typically instantiated directly, but is used internally
 * by the krb5-auth library.
 */
static VALUE rkrb5_context_initialize(VALUE self){
  RUBY_KRB5_CONTEXT* ptr;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_CONTEXT, &krb5_context_type, ptr);

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  return self;
}

void Init_context(){
  /* The Kerberos::Krb5::Context class encapsulates a Kerberos context. */
  cKrb5Context = rb_define_class_under(cKrb5, "Context", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5Context, rkrb5_context_allocate);

  // Constructor
  rb_define_method(cKrb5Context, "initialize", rkrb5_context_initialize, 0);

  // Instance Methods
  rb_define_method(cKrb5Context, "close", rkrb5_context_close, 0);
}
