#include <rkerberos.h>

VALUE cKrb5Principal;


// TypedData functions for RUBY_KRB5_PRINC
static void rkrb5_princ_typed_mark(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_PRINC *p = (RUBY_KRB5_PRINC *)ptr;
  if (p->rb_context != Qnil)
    rb_gc_mark(p->rb_context);
}

static void rkrb5_princ_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_PRINC *p = (RUBY_KRB5_PRINC *)ptr;
  if (p->principal)
    krb5_free_principal(p->ctx, p->principal);
  if (p->ctx && p->rb_context == Qnil)
    krb5_free_context(p->ctx);
  else if (p->rb_context != Qnil)
    rkrb5_context_release(p->rb_context);
  free(p);
}

static size_t rkrb5_princ_typed_size(const void *ptr) {
  return sizeof(RUBY_KRB5_PRINC);
}

static const rb_data_type_t rkrb5_princ_data_type = {
  "RUBY_KRB5_PRINC",
  {rkrb5_princ_typed_mark, rkrb5_princ_typed_free, rkrb5_princ_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5::Principal class.
static VALUE rkrb5_princ_allocate(VALUE klass){
  RUBY_KRB5_PRINC* ptr = ALLOC(RUBY_KRB5_PRINC);
  memset(ptr, 0, sizeof(RUBY_KRB5_PRINC));
  ptr->rb_context = Qnil;
  return TypedData_Wrap_Struct(klass, &rkrb5_princ_data_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::Krb5::Principal.new(name: nil, context: nil)
 *
 * Creates and returns a new Krb5::Principal object. If a block is provided
 * then it yields itself.
 *
 * A principal +name+ may be provided as a keyword argument. If not provided
 * or nil, the principal attribute will be nil.
 *
 * An optional +context+ keyword argument may be provided. If given, it must
 * be a Kerberos::Krb5::Context object and will be used instead of creating
 * a new context via krb5_init_context.
 *
 * Example:
 *
 *   principal1 = Kerberos::Krb5::Principal.new(name: 'Jon')
 *
 *   principal2 = Kerberos::Krb5::Principal.new(name: 'Jon') do |pr|
 *     pr.expire_time = Time.now + 20000
 *   end
 *
 *   ctx = Kerberos::Krb5::Context.new
 *   principal3 = Kerberos::Krb5::Principal.new(name: 'Jon', context: ctx)
 */
static VALUE rkrb5_princ_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_PRINC* ptr;
  krb5_error_code kerror;
  VALUE v_opts = Qnil;
  VALUE v_name = Qnil;
  VALUE v_context = Qnil;
  ID kw_table[2] = { rb_intern("name"), rb_intern("context") };
  VALUE kw_vals[2];

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    v_opts = rb_hash_new();

  rb_get_kwargs(v_opts, kw_table, 0, 2, kw_vals);
  v_name = kw_vals[0] == Qundef ? Qnil : kw_vals[0];
  v_context = kw_vals[1] == Qundef ? Qnil : kw_vals[1];

  // Initialize or borrow the context
  if(!NIL_P(v_context)){
    ptr->ctx = rkrb5_context_borrow(v_context);
    ptr->rb_context = v_context;
  }
  else{
    kerror = krb5_init_context(&ptr->ctx);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_init_context failed: %s", error_message(kerror));

    ptr->rb_context = Qnil;
  }

  if(NIL_P(v_name)){
    rb_iv_set(self, "@principal", Qnil);
  }
  else{
    char* name;
    Check_Type(v_name, T_STRING);

    name = StringValueCStr(v_name);
    kerror = krb5_parse_name(ptr->ctx, name, &ptr->principal);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_parse_name failed: %s", error_message(kerror));

    rb_iv_set(self, "@principal", v_name);
  }

  rb_iv_set(self, "@attributes", Qnil);
  rb_iv_set(self, "@aux_attributes", Qnil);
  rb_iv_set(self, "@expire_time", Qnil);
  rb_iv_set(self, "@fail_auth_count", Qnil);
  rb_iv_set(self, "@last_failed", Qnil);
  rb_iv_set(self, "@last_password_change", Qnil);
  rb_iv_set(self, "@last_success", Qnil);
  rb_iv_set(self, "@max_life", Qnil);
  rb_iv_set(self, "@max_renewable_life", Qnil);
  rb_iv_set(self, "@mod_date", Qnil);
  rb_iv_set(self, "@mod_name", Qnil);
  rb_iv_set(self, "@password_expiration", Qnil);
  rb_iv_set(self, "@policy", Qnil);
  rb_iv_set(self, "@kvno", Qnil);

  if(rb_block_given_p())
    rb_yield(self);

  return self;
}

/*
 * call-seq:
 *   principal.close
 *
 * Releases the principal and its Kerberos context lease. Once closed, the
 * principal cannot be reused.
 */
static VALUE rkrb5_princ_close(VALUE self){
  RUBY_KRB5_PRINC* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  if(!ptr->ctx)
    return self;

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->rb_context == Qnil)
    krb5_free_context(ptr->ctx);
  else
    rkrb5_context_release(ptr->rb_context);

  ptr->ctx = NULL;
  ptr->principal = NULL;
  ptr->rb_context = Qnil;

  return self;
}

/*
 * call-seq:
 *   principal.realm
 *
 * Returns the realm for the given principal.
 */
static VALUE rkrb5_princ_get_realm(VALUE self){
  RUBY_KRB5_PRINC* ptr;
  krb5_data* realm;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  if(!ptr->principal)
    rb_raise(cKrb5Exception, "no principal has been established");

  realm = krb5_princ_realm(ptr->ctx, ptr->principal);

  return rb_str_new(realm->data, realm->length);
}

/*
 * call-seq:
 *   principal.realm = 'YOUR.REALM'
 *
 * Sets the realm for the given principal.
 */
static VALUE rkrb5_princ_set_realm(VALUE self, VALUE v_realm){
  RUBY_KRB5_PRINC* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  if(!ptr->principal)
    rb_raise(cKrb5Exception, "no principal has been established");

  Check_Type(v_realm, T_STRING);

  krb5_set_principal_realm(ptr->ctx, ptr->principal, StringValueCStr(v_realm));

  return v_realm;
}

/*
 * call-seq:
 *   principal1 == principal2
 *
 * Returns whether or not two principals are the same.
 */
static VALUE rkrb5_princ_equal(VALUE self, VALUE v_other){
  RUBY_KRB5_PRINC* ptr1;
  RUBY_KRB5_PRINC* ptr2;
  VALUE v_bool = Qfalse;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr1);

  if(!rb_obj_is_kind_of(v_other, cKrb5Principal))
    return Qfalse;

  TypedData_Get_Struct(v_other, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr2);

  if(!ptr1->principal || !ptr2->principal)
    return Qfalse;

  if(krb5_principal_compare(ptr1->ctx, ptr1->principal, ptr2->principal))
    v_bool = Qtrue;

  return v_bool;
}

/*
 * call-seq:
 *   principal.inspect
 *
 * A custom inspect method for the Principal object.
 */
static VALUE rkrb5_princ_inspect(VALUE self){
  VALUE v_str;

  v_str = rb_str_new2("#<");
  rb_str_buf_cat2(v_str, rb_obj_classname(self));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "attributes=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@attributes")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "aux_attributes=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@aux_attributes")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "expire_time=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@expire_time")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "fail_auth_count=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@fail_auth_count")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "kvno=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@kvno")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_failed=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_failed")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_password_change=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_password_change")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_success=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_success")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "max_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@max_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "max_renewable_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@max_renewable_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mod_date=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mod_date")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mod_name=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mod_name")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "password_expiration=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@password_expiration")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "policy=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@policy")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "principal=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@principal")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, ">");

  return v_str;
}

/*
 * call-seq:
 *   principal.principal_type -> Integer
 *
 * Returns the type of the principal as an integer, e.g.
 * KRB5_NT_PRINCIPAL (1), KRB5_NT_SRV_HST (2), etc.
 */
static VALUE rkrb5_princ_get_type(VALUE self){
  RUBY_KRB5_PRINC* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  if(!ptr->principal)
    rb_raise(cKrb5Exception, "no principal has been established");

  return INT2FIX(krb5_princ_type(ptr->ctx, ptr->principal));
}

/*
 * call-seq:
 *   principal.components -> Array
 *
 * Returns an array of the component strings that make up this principal
 * name (excluding the realm). For example, "admin/instance@REALM" would
 * return ["admin", "instance"].
 */
static VALUE rkrb5_princ_components(VALUE self){
  RUBY_KRB5_PRINC* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_PRINC, &rkrb5_princ_data_type, ptr);

  if(!ptr->principal)
    rb_raise(cKrb5Exception, "no principal has been established");

  int n = krb5_princ_size(ptr->ctx, ptr->principal);
  VALUE v_array = rb_ary_new_capa(n);

  for(int i = 0; i < n; i++){
    krb5_data* component = krb5_princ_component(ptr->ctx, ptr->principal, i);
    rb_ary_push(v_array, rb_str_new(component->data, component->length));
  }

  return v_array;
}

void Init_principal(void){
  /* The Kerberos::Krb5::Principal class encapsulates a Kerberos principal. */
  cKrb5Principal = rb_define_class_under(cKrb5, "Principal", rb_cObject);

  // Allocation Function

  rb_define_alloc_func(cKrb5Principal, rkrb5_princ_allocate);

  // Constructor

  rb_define_method(cKrb5Principal, "initialize", rkrb5_princ_initialize, -1);

  // Instance Methods

  rb_define_method(cKrb5Principal, "inspect", rkrb5_princ_inspect, 0);
  rb_define_method(cKrb5Principal, "realm", rkrb5_princ_get_realm, 0);
  rb_define_method(cKrb5Principal, "realm=", rkrb5_princ_set_realm, 1);
  rb_define_method(cKrb5Principal, "==", rkrb5_princ_equal, 1);
  rb_define_method(cKrb5Principal, "principal_type", rkrb5_princ_get_type, 0);
  rb_define_method(cKrb5Principal, "components", rkrb5_princ_components, 0);
  rb_define_method(cKrb5Principal, "close", rkrb5_princ_close, 0);

  // Attributes

  rb_define_attr(cKrb5Principal, "attributes", 1, 1);
  rb_define_attr(cKrb5Principal, "aux_attributes", 1, 1);
  rb_define_attr(cKrb5Principal, "expire_time", 1, 1);
  rb_define_attr(cKrb5Principal, "fail_auth_count", 1, 1);
  rb_define_attr(cKrb5Principal, "kvno", 1, 1);
  rb_define_attr(cKrb5Principal, "last_failed", 1, 1);
  rb_define_attr(cKrb5Principal, "last_password_change", 1, 1);
  rb_define_attr(cKrb5Principal, "last_success", 1, 1);
  rb_define_attr(cKrb5Principal, "max_life", 1, 1);
  rb_define_attr(cKrb5Principal, "max_renewable_life", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_date", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_name", 1, 1);
  rb_define_attr(cKrb5Principal, "password_expiration", 1, 1);
  rb_define_attr(cKrb5Principal, "policy", 1, 1);
  rb_define_attr(cKrb5Principal, "principal", 1, 0);

  // Aliases

  rb_define_alias(cKrb5Principal, "name", "principal");
}
