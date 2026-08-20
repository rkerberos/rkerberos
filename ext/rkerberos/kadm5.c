#ifdef HAVE_KADM5_ADMIN_H
#include <rkerberos.h>
#include <kdb.h>

VALUE cKadm5;
VALUE cKadm5Exception;
VALUE cKadm5PrincipalNotFoundException;

// Prototype
static VALUE rkadm5_close(VALUE);
static void free_tl_data(krb5_tl_data *);
static void free_db_args(char**);
char** parse_db_args(VALUE v_db_args);
void add_db_args(kadm5_principal_ent_rec*, char**);
void add_tl_data(krb5_int16 *, krb5_tl_data **,
  krb5_int16, krb5_ui_2, krb5_octet *);


// TypedData functions for RUBY_KADM5
static void rkadm5_typed_mark(void *ptr) {
  if (!ptr) return;
  RUBY_KADM5 *k = (RUBY_KADM5 *)ptr;
  if (k->rb_context != Qnil)
    rb_gc_mark(k->rb_context);
}

static void rkadm5_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KADM5 *k = (RUBY_KADM5 *)ptr;
  if (k->handle)
    kadm5_destroy(k->handle);
  if (k->princ)
    krb5_free_principal(k->ctx, k->princ);
  if (k->ctx && k->rb_context == Qnil)
    krb5_free_context(k->ctx);
  free_db_args(k->db_args);
  free(k);
}

static size_t rkadm5_typed_size(const void *ptr) {
  return sizeof(RUBY_KADM5);
}

static const rb_data_type_t rkadm5_data_type = {
  "RUBY_KADM5",
  {rkadm5_typed_mark, rkadm5_typed_free, rkadm5_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Kadm5 class.
static VALUE rkadm5_allocate(VALUE klass){
  RUBY_KADM5* ptr = ALLOC(RUBY_KADM5);
  memset(ptr, 0, sizeof(RUBY_KADM5));
  ptr->rb_context = Qnil;
  return TypedData_Wrap_Struct(klass, &rkadm5_data_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::Kadm5.new(:principal => 'name', :password => 'xxxxx')
 *   Kerberos::Kadm5.new(:principal => 'name', :keytab => '/path/to/your/keytab')
 *   Kerberos::Kadm5.new(:principal => 'name', :keytab => true)
 *   Kerberos::Kadm5.new(:principal => 'name', :ccache => ccache_object)
 *
 * Creates and returns a new Kerberos::Kadm5 object. A hash argument is
 * accepted that allows you to specify a principal and a password, or
 * a keytab file, or a credentials cache.
 *
 * If you pass a string as the :keytab value it will attempt to use that file
 * for the keytab. If you pass true as the value it will attempt to use the
 * default keytab file, typically /etc/krb5.keytab.
 *
 * If you pass a Kerberos::Krb5::CredentialsCache object as the :ccache value,
 * it will authenticate using the credentials stored in that cache via
 * kadm5_init_with_creds.
 *
 * You may also pass the :service option to specify the service name. The
 * default is kadmin/admin.
 *
 * There is also a :db_args option, which is a single string or array of strings
 * containing options usually passed to kadmin with the -x switch. For a list of
 * available options, see the kadmin manpage.
 *
 * Only one of :password, :keytab, or :ccache may be specified.
 *
 */
static VALUE rkadm5_initialize(VALUE self, VALUE v_opts){
  RUBY_KADM5* ptr;
  VALUE v_principal, v_password, v_keytab, v_service, v_db_args, v_context, v_ccache;
  char* user;
  char* pass = NULL;
  char* keytab = NULL;
  char* service = NULL;
  char default_keytab_name[MAX_KEYTAB_NAME_LEN];
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  Check_Type(v_opts, T_HASH);

  v_principal = rb_hash_aref2(v_opts, ID2SYM(rb_intern("principal")));
  v_password = rb_hash_aref2(v_opts, ID2SYM(rb_intern("password")));
  v_keytab = rb_hash_aref2(v_opts, ID2SYM(rb_intern("keytab")));
  v_ccache = rb_hash_aref2(v_opts, ID2SYM(rb_intern("ccache")));

  // Validate mutual exclusivity
  {
    int auth_count = 0;
    if(RTEST(v_password)) auth_count++;
    if(RTEST(v_keytab))   auth_count++;
    if(RTEST(v_ccache))   auth_count++;

    if(auth_count > 1)
      rb_raise(rb_eArgError, "only one of password, keytab, or ccache may be specified");

    if(auth_count == 0)
      rb_raise(rb_eArgError, "one of password, keytab, or ccache must be specified");
  }

  // Principal must be specified if using a password
  if(RTEST(v_password)){
    if(NIL_P(v_principal))
      rb_raise(rb_eArgError, "principal must be specified");

    Check_Type(v_password, T_STRING);
    Check_Type(v_principal, T_STRING);

    pass = StringValueCStr(v_password);
  }

  if(RTEST(v_ccache) && NIL_P(v_principal)){
    if(NIL_P(v_principal))
      v_principal = rb_funcall(v_ccache, rb_intern("principal"), 0);
  }

  // For a keytab use the first entry's principal
  if(RTEST(v_keytab) && NIL_P(v_principal)) {
    VALUE v_enum, v_first;
    v_enum = rb_funcall(v_keytab, rb_intern("each"), 0);
    v_first = rb_funcall(v_enum, rb_intern("first"), 0);
    v_principal = rb_iv_get(v_first, "@principal");
  }

  user = StringValueCStr(v_principal);
  v_service = rb_hash_aref2(v_opts, ID2SYM(rb_intern("service")));

  if(NIL_P(v_service)){
    service = (char *) "kadmin/admin";
  }
  else{
    Check_Type(v_service, T_STRING);
    service = StringValueCStr(v_service);
  }

  v_db_args = rb_hash_aref2(v_opts, ID2SYM(rb_intern("db_args")));
  ptr->db_args = parse_db_args(v_db_args);

  v_context = rb_hash_aref2(v_opts, ID2SYM(rb_intern("context")));

  // Initialize or borrow the context
  if(RTEST(v_context)){
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
      rb_raise(cKadm5Exception, "krb5_init_context: %s", error_message(kerror));

    ptr->rb_context = Qnil;
  }

  // The docs say I can use NULL to get the default, but reality appears to be otherwise.
  if(RTEST(v_keytab)){
    if(TYPE(v_keytab) == T_TRUE){
      kerror = krb5_kt_default_name(ptr->ctx, default_keytab_name, MAX_KEYTAB_NAME_LEN);

      if(kerror)
        rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

      keytab = default_keytab_name;
    }
    else{
      Check_Type(v_keytab, T_STRING);
      keytab = StringValueCStr(v_keytab);
    }
  }

  if(RTEST(v_password)){
    kerror = kadm5_init_with_password(
      ptr->ctx,
      user,
      pass,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_3,
      ptr->db_args,
      &ptr->handle
    );

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_password: %s", error_message(kerror));
  }
  else if(RTEST(v_keytab)){
    kerror = kadm5_init_with_skey(
      ptr->ctx,
      user,
      keytab,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_3,
      ptr->db_args,
      &ptr->handle
    );

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_skey: %s", error_message(kerror));
  }
  else if(RTEST(v_ccache)){
    RUBY_KRB5_CCACHE* cc_ptr;

    if(!rb_obj_is_kind_of(v_ccache, cKrb5CCache))
      rb_raise(rb_eTypeError, "ccache must be a Kerberos::Krb5::CredentialsCache object");

    TypedData_Get_Struct(v_ccache, RUBY_KRB5_CCACHE, &rkrb5_ccache_data_type, cc_ptr);

    if(!cc_ptr->ccache)
      rb_raise(cKrb5Exception, "credentials cache is closed or destroyed");

    kerror = kadm5_init_with_creds(
      ptr->ctx,
      user,
      cc_ptr->ccache,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_3,
      ptr->db_args,
      &ptr->handle
    );

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_creds: %s", error_message(kerror));
  }

  if(rb_block_given_p()){
    rb_ensure(rb_yield, self, rkadm5_close, self);
    return Qnil;
  }

  return self;
}

/* call-seq:
 *   kadm5.set_password(user, password)
 *
 * Set the password for +user+ (i.e. the principal) to +password+.
 */
static VALUE rkadm5_set_password(VALUE self, VALUE v_user, VALUE v_pass){
  RUBY_KADM5* ptr;
  krb5_error_code kerror;
  char *user;
  char *pass;

  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  user = StringValueCStr(v_user);
  pass = StringValueCStr(v_pass);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(ptr->princ){
    krb5_free_principal(ptr->ctx, ptr->princ);
    ptr->princ = NULL;
  }

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_chpass_principal(ptr->handle, ptr->princ, pass);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_chpass_principal: %s", error_message(kerror));

  return self;
}

/* call-seq:
 *   kadm5.set_pwexpire(user, pwexpire)
 *
 * Set the password expire date for +user+ (i.e. the principal) to +pwexpire+.
 */
static VALUE rkadm5_set_pwexpire(VALUE self, VALUE v_user, VALUE v_pwexpire){
  Check_Type(v_user, T_STRING);
  Check_Type(v_pwexpire, T_FIXNUM);

  RUBY_KADM5* ptr;
  kadm5_principal_ent_rec ent;
  char* user = StringValuePtr(v_user);
  int pwexpire = NUM2INT(v_pwexpire);
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(ptr->princ){
    krb5_free_principal(ptr->ctx, ptr->princ);
    ptr->princ = NULL;
  }

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  memset(&ent, 0, sizeof(ent));
  kerror = kadm5_get_principal(
    ptr->handle,
    ptr->princ,
    &ent,
    KADM5_PRINCIPAL_NORMAL_MASK
  );

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_get_principal: %s", error_message(kerror));

  ent.pw_expiration=pwexpire;
  kerror = kadm5_modify_principal(ptr->handle, &ent, KADM5_PW_EXPIRATION);

  kadm5_free_principal_ent(ptr->handle, &ent);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_set_pwexpire: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   kadm5.create_principal(name:, password:, db_args: nil)
 *   kadm5.create_principal(principal:, password:, db_args: nil)
 *
 * Creates a new principal with an initial password of +password+.
 *
 * The principal may be specified either as a +name+ string or as a
 * +principal+ object (a Kerberos::Krb5::Principal). When a Principal
 * object is provided, any non-nil writable attributes on that object
 * are forwarded to the KDC:
 *
 *   * +policy+
 *   * +expire_time+
 *   * +password_expiration+
 *   * +max_life+
 *   * +max_renewable_life+
 *   * +attributes+
 *
 * +db_args+ is an optional string or array of strings containing options
 * that are usually passed to add_principal with the -x option. For a
 * list of options, see the kadmin manpage, in the add_principal section.
 */
static VALUE rkadm5_create_principal(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  char* pass;
  char** db_args;
  int mask;
  kadm5_principal_ent_rec princ;
  krb5_error_code kerror;
  VALUE v_opts, v_name, v_principal, v_pass, v_db_args;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    rb_raise(rb_eArgError, "name: (or principal:) and password: are required");

  v_name      = rb_hash_aref2(v_opts, ID2SYM(rb_intern("name")));
  v_principal = rb_hash_aref2(v_opts, ID2SYM(rb_intern("principal")));
  v_pass      = rb_hash_aref2(v_opts, ID2SYM(rb_intern("password")));
  v_db_args   = rb_hash_aref2(v_opts, ID2SYM(rb_intern("db_args")));

  if(NIL_P(v_pass))
    rb_raise(rb_eArgError, "password: is required");

  Check_Type(v_pass, T_STRING);

  if(NIL_P(v_name) && NIL_P(v_principal))
    rb_raise(rb_eArgError, "name: or principal: is required");

  if(RTEST(v_name) && RTEST(v_principal))
    rb_raise(rb_eArgError, "name: and principal: are mutually exclusive");

  memset(&princ, 0, sizeof(princ));

  mask = KADM5_PRINCIPAL | KADM5_TL_DATA;
  pass = StringValueCStr(v_pass);

  db_args = parse_db_args(v_db_args);
  add_db_args(&princ, db_args);
  free_db_args(db_args);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  // Determine the principal name and populate mask from the principal object
  if(RTEST(v_principal)){
    VALUE v_princ_name, v_policy, v_expire, v_pw_expire, v_max_life, v_max_renew, v_attrs;

    if(!rb_obj_is_kind_of(v_principal, cKrb5Principal))
      rb_raise(rb_eTypeError, "principal: must be a Kerberos::Krb5::Principal object");

    v_princ_name = rb_iv_get(v_principal, "@principal");

    if(NIL_P(v_princ_name))
      rb_raise(rb_eArgError, "principal object has no name set");

    Check_Type(v_princ_name, T_STRING);

    kerror = krb5_parse_name(ptr->ctx, StringValueCStr(v_princ_name), &princ.principal);

    if(kerror){
      free_tl_data(princ.tl_data);
      rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));
    }

    // Forward optional attributes from the Principal object
    v_policy = rb_iv_get(v_principal, "@policy");

    if(RTEST(v_policy)){
      Check_Type(v_policy, T_STRING);
      princ.policy = StringValueCStr(v_policy);
      mask |= KADM5_POLICY;
    }

    v_expire = rb_iv_get(v_principal, "@expire_time");

    if(RTEST(v_expire)){
      princ.princ_expire_time = (krb5_timestamp)NUM2LONG(rb_funcall(v_expire, rb_intern("to_i"), 0));
      mask |= KADM5_PRINC_EXPIRE_TIME;
    }

    v_pw_expire = rb_iv_get(v_principal, "@password_expiration");

    if(RTEST(v_pw_expire)){
      princ.pw_expiration = (krb5_timestamp)NUM2LONG(rb_funcall(v_pw_expire, rb_intern("to_i"), 0));
      mask |= KADM5_PW_EXPIRATION;
    }

    v_max_life = rb_iv_get(v_principal, "@max_life");

    if(RTEST(v_max_life)){
      princ.max_life = NUM2LONG(v_max_life);
      mask |= KADM5_MAX_LIFE;
    }

    v_max_renew = rb_iv_get(v_principal, "@max_renewable_life");

    if(RTEST(v_max_renew)){
      princ.max_renewable_life = NUM2LONG(v_max_renew);
      mask |= KADM5_MAX_RLIFE;
    }

    v_attrs = rb_iv_get(v_principal, "@attributes");

    if(RTEST(v_attrs)){
      princ.attributes = NUM2LONG(v_attrs);
      mask |= KADM5_ATTRIBUTES;
    }
  }
  else{
    Check_Type(v_name, T_STRING);

    kerror = krb5_parse_name(ptr->ctx, StringValueCStr(v_name), &princ.principal);

    if(kerror){
      free_tl_data(princ.tl_data);
      rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));
    }
  }

  kerror = kadm5_create_principal(ptr->handle, &princ, mask, pass);

  if(kerror){
    krb5_free_principal(ptr->ctx, princ.principal);
    free_tl_data(princ.tl_data);
    rb_raise(cKadm5Exception, "kadm5_create_principal: %s", error_message(kerror));
  }

  krb5_free_principal(ptr->ctx, princ.principal);
  free_tl_data(princ.tl_data);

  return self;
}

/* call-seq:
 *   kadm5.delete_principal(name)
 *
 * Deletes the principal +name+ from the Kerberos database.
 */
static VALUE rkadm5_delete_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  char* user;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(ptr->princ){
    krb5_free_principal(ptr->ctx, ptr->princ);
    ptr->princ = NULL;
  }

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_delete_principal(ptr->handle, ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_delete_principal: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   kadm5.close
 *
 * Closes the kadm5 object. Specifically, it frees the principal and context
 * associated with the kadm5 object, as well as the server handle.
 *
 * Any attempt to call a method on a kadm5 object after it has been closed
 * will fail with an error message indicating a lack of context.
 */
static VALUE rkadm5_close(VALUE self){
  RUBY_KADM5* ptr;
  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  if(ptr->handle)
    kadm5_destroy(ptr->handle);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx && ptr->rb_context == Qnil)
    krb5_free_context(ptr->ctx);

  free_db_args(ptr->db_args);

  ptr->db_args = NULL;
  ptr->ctx    = NULL;
  ptr->princ  = NULL;
  ptr->handle = NULL;
  ptr->rb_context = Qnil;

  return self;
}

// Private function for creating a Principal object from a entry record.
static VALUE create_principal_from_entry(VALUE v_name, RUBY_KADM5* ptr, kadm5_principal_ent_rec* ent){
  krb5_error_code kerror;
  VALUE v_principal;
  VALUE v_opts = rb_hash_new();

  rb_hash_aset(v_opts, ID2SYM(rb_intern("name")), v_name);

  v_principal = rb_class_new_instance_kw(1, &v_opts, cKrb5Principal, RB_PASS_KEYWORDS);

  rb_iv_set(v_principal, "@attributes", LONG2FIX(ent->attributes));
  rb_iv_set(v_principal, "@aux_attributes", INT2FIX(ent->aux_attributes));

  if(ent->princ_expire_time)
    rb_iv_set(v_principal, "@expire_time", rb_time_new(ent->princ_expire_time, 0));

  rb_iv_set(v_principal, "@fail_auth_count", INT2FIX(ent->fail_auth_count));
  rb_iv_set(v_principal, "@kvno", INT2FIX(ent->kvno));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_failed", rb_time_new(ent->last_failed, 0));

  if(ent->last_pwd_change)
    rb_iv_set(v_principal, "@last_password_change", rb_time_new(ent->last_pwd_change, 0));

  if(ent->last_success)
    rb_iv_set(v_principal, "@last_success", rb_time_new(ent->last_success, 0));

  rb_iv_set(v_principal, "@max_life", LONG2FIX(ent->max_life));
  rb_iv_set(v_principal, "@max_renewable_life", LONG2FIX(ent->max_renewable_life));

  if(ent->mod_date)
    rb_iv_set(v_principal, "@mod_date", rb_time_new(ent->mod_date, 0));

  if(ent->mod_name){
    char* mod_name;
    kerror = krb5_unparse_name(ptr->ctx, ent->mod_name, &mod_name);

    if(kerror){
      kadm5_free_principal_ent(ptr->handle, ent);
      rb_raise(cKadm5Exception, "krb5_unparse_name: %s", error_message(kerror));
    }

    rb_iv_set(v_principal, "@mod_name", rb_str_new2(mod_name));
    krb5_free_unparsed_name(ptr->ctx, mod_name);
  }

  if(ent->pw_expiration)
    rb_iv_set(v_principal, "@password_expiration", rb_time_new(ent->pw_expiration, 0));

  if(ent->policy)
    rb_iv_set(v_principal, "@policy", rb_str_new2(ent->policy));

  kadm5_free_principal_ent(ptr->handle, ent);

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.find_principal(principal_name)
 *
 * Returns a Principal object for +principal_name+ containing various bits
 * of information regarding that principal, such as policy, attributes,
 * expiration information, etc.
 *
 * Unlike the get_principal method, this method returns nil if the principal
 * cannot be found instead of raising an error.
 */
static VALUE rkadm5_find_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  VALUE v_principal;
  char* user;
  int mask;
  kadm5_principal_ent_rec ent;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(ptr->princ){
    krb5_free_principal(ptr->ctx, ptr->princ);
    ptr->princ = NULL;
  }

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  mask = KADM5_PRINCIPAL_NORMAL_MASK;

  kerror = kadm5_get_principal(
    ptr->handle,
    ptr->princ,
    &ent,
    mask
  );

  // Return nil if not found instead of raising an error.
  if(kerror){
    if(kerror == KADM5_UNK_PRINC)
      v_principal = Qnil;
    else
      rb_raise(cKadm5Exception, "kadm5_get_principal: %s", error_message(kerror));
  }
  else{
    v_principal = create_principal_from_entry(v_user, ptr, &ent);
  }

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.get_principal(principal_name)
 *
 * Returns a Principal object for +principal_name+ containing various bits
 * of information regarding that principal, such as policy, attributes,
 * expiration information, etc.
 *
 * If the +principal_name+ cannot be found then a PrincipalNotFoundException
 * is raised.
 */
static VALUE rkadm5_get_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  VALUE v_principal;
  char* user;
  int mask;
  kadm5_principal_ent_rec ent;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(ptr->princ){
    krb5_free_principal(ptr->ctx, ptr->princ);
    ptr->princ = NULL;
  }

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  mask = KADM5_PRINCIPAL_NORMAL_MASK;

  kerror = kadm5_get_principal(
    ptr->handle,
    ptr->princ,
    &ent,
    mask
  );

  if(kerror){
    if(kerror == KADM5_UNK_PRINC)
      rb_raise(cKadm5PrincipalNotFoundException, "principal not found");
    else
      rb_raise(cKadm5Exception, "kadm5_get_principal: %s", error_message(kerror));
  }

  v_principal = create_principal_from_entry(v_user, ptr, &ent);

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.create_policy(policy)
 *
 * Creates a new Kerberos policy based on the Policy object.
 *
 * Example:
 *
 *   # Using a Policy object
 *   policy = Kerberos::Kadm5::Policy.new(:name => 'test', :min_length => 5)
 *   kadm5.create_policy(policy)
 *
 *   # Using a hash
 *   kadm5.create_policy(:name => 'test', :min_length => 5)
 */
static VALUE rkadm5_create_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  kadm5_ret_t kerror;
  kadm5_policy_ent_rec ent;
  long mask = KADM5_POLICY;
  VALUE v_name, v_min_classes, v_min_life, v_max_life, v_min_length, v_history_num;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  // Allow a hash or a Policy object
  if(rb_obj_is_kind_of(v_policy, rb_cHash)){
    VALUE v_args[1];
    v_args[0] = v_policy;
    v_policy = rb_class_new_instance(1, v_args, cKadm5Policy);
  }

  v_name        = rb_iv_get(v_policy, "@policy");
  v_min_classes = rb_iv_get(v_policy, "@min_classes");
  v_min_length  = rb_iv_get(v_policy, "@min_length");
  v_min_life    = rb_iv_get(v_policy, "@min_life");
  v_max_life    = rb_iv_get(v_policy, "@max_life");
  v_history_num = rb_iv_get(v_policy, "@history_num");

  memset(&ent, 0, sizeof(ent));
  ent.policy = StringValueCStr(v_name);

  if(RTEST(v_min_classes)){
    mask |= KADM5_PW_MIN_CLASSES;
    ent.pw_min_classes = NUM2LONG(v_min_classes);
  }

  if(RTEST(v_min_length)){
    mask |= KADM5_PW_MIN_LENGTH;
    ent.pw_min_length = NUM2LONG(v_min_length);
  }

  if(RTEST(v_min_life)){
    mask |= KADM5_PW_MIN_LIFE;
    ent.pw_min_life = NUM2LONG(v_min_life);
  }

  if(RTEST(v_max_life)){
    mask |= KADM5_PW_MAX_LIFE;
    ent.pw_max_life = NUM2LONG(v_max_life);
  }

  if(RTEST(v_history_num)){
    mask |= KADM5_PW_HISTORY_NUM;
    ent.pw_history_num = NUM2LONG(v_history_num);
  }

  kerror = kadm5_create_policy(ptr->handle, &ent, mask);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_create_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

/*
 * call-seq:
 *   kadm5.delete_policy(name)
 *
 * Deletes the Kerberos policy +name+.
 *
 * Example:
 *
 *   kadm5.delete_policy('test')
 */
static VALUE rkadm5_delete_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  kadm5_ret_t kerror;
  char* policy;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  policy = StringValueCStr(v_policy);

  kerror = kadm5_delete_policy(ptr->handle, policy);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_delete_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

/*
 * call-seq:
 *   kadm5.get_policy(name)
 *
 * Get and return a Policy object for +name+. If the +name+ cannot be found,
 * then an exception is raised.
 *
 * This method is nearly identical to kadm5.find_policy, except that method
 * returns nil if not found.
 */
static VALUE rkadm5_get_policy(VALUE self, VALUE v_name){
  RUBY_KADM5* ptr;
  VALUE v_policy = Qnil;
  kadm5_policy_ent_rec ent;
  kadm5_ret_t kerror;
  char* policy_name;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  policy_name = StringValueCStr(v_name);

  kerror = kadm5_get_policy(ptr->handle, policy_name, &ent);

  if(kerror){
    rb_raise(
      cKadm5Exception,
      "kadm5_get_policy: %s (%li)", error_message(kerror), kerror
    );
  }
  else{
    VALUE v_arg[1];
    VALUE v_hash = rb_hash_new();

    rb_hash_aset(v_hash, rb_str_new2("name"), rb_str_new2(ent.policy));
    rb_hash_aset(v_hash, rb_str_new2("min_life"), LONG2FIX(ent.pw_min_life));
    rb_hash_aset(v_hash, rb_str_new2("max_life"), LONG2FIX(ent.pw_max_life));
    rb_hash_aset(v_hash, rb_str_new2("min_length"), LONG2FIX(ent.pw_min_length));
    rb_hash_aset(v_hash, rb_str_new2("min_classes"), LONG2FIX(ent.pw_min_classes));
    rb_hash_aset(v_hash, rb_str_new2("history_num"), LONG2FIX(ent.pw_history_num));

    v_arg[0] = v_hash;

    v_policy = rb_class_new_instance(1, v_arg, cKadm5Policy);

    kadm5_free_policy_ent(ptr->handle, &ent);
  }

  return v_policy;
}

/*
 * call-seq:
 *   kadm5.find_policy(name)
 *
 * Get and return a Policy object for +name+. If the +name+ cannot be found,
 * then nil is returned.
 *
 * This method is nearly identical to kadm5.get_policy, except that method
 * raises an exception if not found.
 */
static VALUE rkadm5_find_policy(VALUE self, VALUE v_name){
  RUBY_KADM5* ptr;
  VALUE v_policy = Qnil;
  kadm5_policy_ent_rec ent;
  kadm5_ret_t kerror;
  char* policy_name;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  policy_name = StringValueCStr(v_name);

  kerror = kadm5_get_policy(ptr->handle, policy_name, &ent);

  // Return nil if not found rather than raising an error.
  if(kerror){
    if(kerror != KADM5_UNK_POLICY){
      rb_raise(
        cKadm5Exception,
        "kadm5_get_policy: %s (%li)", error_message(kerror), kerror
      );
    }
  }
  else{
    VALUE v_arg[1];
    VALUE v_hash = rb_hash_new();

    rb_hash_aset(v_hash, rb_str_new2("name"), rb_str_new2(ent.policy));
    rb_hash_aset(v_hash, rb_str_new2("min_life"), LONG2FIX(ent.pw_min_life));
    rb_hash_aset(v_hash, rb_str_new2("max_life"), LONG2FIX(ent.pw_max_life));
    rb_hash_aset(v_hash, rb_str_new2("min_length"), LONG2FIX(ent.pw_min_length));
    rb_hash_aset(v_hash, rb_str_new2("min_classes"), LONG2FIX(ent.pw_min_classes));
    rb_hash_aset(v_hash, rb_str_new2("history_num"), LONG2FIX(ent.pw_history_num));

    v_arg[0] = v_hash;

    v_policy = rb_class_new_instance(1, v_arg, cKadm5Policy);

    kadm5_free_policy_ent(ptr->handle, &ent);
  }

  return v_policy;
}

/*
 * call-seq:
 *   kadm5.modify_policy(policy)
 *
 * Modify an existing Kerberos policy using a +policy+ object.
 *
 * Example:
 *
 *   policy = Kerberos::Kadm5::Policy.find('test')
 *   policy.max_length = 1024
 *   kadm5.modify_policy(policy)
 */
static VALUE rkadm5_modify_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  RUBY_KADM5_POLICY* pptr;
  kadm5_ret_t kerror;
  long mask = KADM5_POLICY;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);
  TypedData_Get_Struct(v_policy, RUBY_KADM5_POLICY, &rkadm5_policy_data_type, pptr);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(pptr->policy.pw_min_classes)
    mask |= KADM5_PW_MIN_CLASSES;

  if(pptr->policy.pw_min_length)
    mask |= KADM5_PW_MIN_LENGTH;

  if(pptr->policy.pw_min_life)
    mask |= KADM5_PW_MIN_LIFE;

  if(pptr->policy.pw_max_life)
    mask |= KADM5_PW_MAX_LIFE;

  kerror = kadm5_modify_policy(ptr->handle, &pptr->policy, mask);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_modify_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

/*
 * call-seq:
 *   kadm5.get_policies(expr = nil)
 *
 * Returns a list of policy names matching +expr+, or all policy names if
 * +expr+ is nil.
 *
 * The valid characters for +expr+ are '*', '?', '[]' and '\'. All other
 * characters match themselves.
 *
 *  kadm5.get_policies          # => Get all policies
 *  kadm5.get_policies('test*') # => Get all policies that start with 'test'
 */
static VALUE rkadm5_get_policies(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  VALUE v_array, v_expr;
  kadm5_ret_t kerror;
  char** pols;
  char* expr;
  int i, count;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  rb_scan_args(argc, argv, "01", &v_expr);

  if(NIL_P(v_expr))
    expr = NULL;
  else
    expr = StringValueCStr(v_expr);

  kerror = kadm5_get_policies(ptr->handle, expr, &pols, &count);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_get_policies: %s (%li)", error_message(kerror), kerror);

  v_array = rb_ary_new();

  for(i = 0; i < count; i++){
    rb_ary_push(v_array, rb_str_new2(pols[i]));
  }

  kadm5_free_name_list(ptr->handle, pols, count);

  return v_array;
}

/*
 * call-seq:
 *   kadm5.get_principals(expr = nil)
 *
 * Returns a list of principals matching +expr+, or all principals if
 * +expr+ is nil.
 *
 * The valid characters for +expr+ are '*', '?', '[]' and '\'. All other
 * characters match themselves.
 *
 * Example:
 *
 *  kadm5.get_principals          # => Get all principals
 *  kadm5.get_principals('test*') # => Get all principals that start with 'test'
 */
static VALUE rkadm5_get_principals(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  VALUE v_array, v_expr;
  kadm5_ret_t kerror;
  char** princs;
  char* expr;
  int i, count;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  rb_scan_args(argc, argv, "01", &v_expr);

  if(NIL_P(v_expr))
    expr = NULL;
  else
    expr = StringValueCStr(v_expr);

  kerror = kadm5_get_principals(ptr->handle, expr, &princs, &count);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_get_principals: %s (%li)", error_message(kerror), kerror);

  v_array = rb_ary_new();

  for(i = 0; i < count; i++){
    rb_ary_push(v_array, rb_str_new2(princs[i]));
  }

  kadm5_free_name_list(ptr->handle, princs, count);

  return v_array;
}

/*
 * call-seq:
 *   kadm5.get_privileges(:strings => false)
 *
 * Returns a numeric bitmask indicating the caller's privileges. If the
 * +strings+ option is true, then an array of human readable strings are
 * returned instead.
 *
 * The possible values, and their string equivalent, are:
 *
 * KADM5_PRIV_GET    (0x01) => "GET"
 * KADM5_PRIV_ADD    (0x02) => "ADD"
 * KADM5_PRIV_MODIFY (0x04) => "MODIFY"
 * KADM5_PRIV_DELETE (0x08) => "DELETE"
 *
 */
static VALUE rkadm5_get_privs(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  VALUE v_return = Qnil;
  VALUE v_strings = Qfalse;
  kadm5_ret_t kerror;
  long privs;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  rb_scan_args(argc, argv, "01", &v_strings);

  kerror = kadm5_get_privs(ptr->handle, &privs);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_get_privs: %s (%li)", error_message(kerror), kerror);

  if(RTEST(v_strings)){
    v_return = rb_ary_new();

    if(privs & KADM5_PRIV_GET)
      rb_ary_push(v_return, rb_str_new2("GET"));
    if(privs & KADM5_PRIV_ADD)
      rb_ary_push(v_return, rb_str_new2("ADD"));
    if(privs & KADM5_PRIV_MODIFY)
      rb_ary_push(v_return, rb_str_new2("MODIFY"));
    if(privs & KADM5_PRIV_DELETE)
      rb_ary_push(v_return, rb_str_new2("DELETE"));
  }
  else{
    v_return = LONG2FIX(privs);
  }

  return v_return;
}

/*
 * call-seq:
 *   kadm.generate_random_key(principal)
 *
 * Generates and assigns a new random key to the named +principal+ and
 * returns the number of generated keys.
 */
static VALUE rkadm5_randkey_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  krb5_keyblock* keys;
  kadm5_ret_t kerror;
  krb5_principal princ;
  char* user;
  int n_keys, i;

  TypedData_Get_Struct(self, RUBY_KADM5, &rkadm5_data_type, ptr);

  user = StringValueCStr(v_user);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_randkey_principal(ptr->handle, princ, &keys, &n_keys);

  if(kerror){
    krb5_free_principal(ptr->ctx, princ);
    rb_raise(cKadm5Exception, "kadm5_randkey_principal: %s (%li)", error_message(kerror), kerror);
  }

  for(i = 0; i < n_keys; i++)
    krb5_free_keyblock_contents(ptr->ctx, &keys[i]);

  free(keys);
  krb5_free_principal(ptr->ctx, princ);

  return INT2NUM(n_keys);
}

/**
 * Parses an array or a single string containing database arguments for kerberos functions.
 * Returns NULL if v_db_args is nil, otherwise returns a NULL-Terminated array of NULL-Terminated strings
 */
char** parse_db_args(VALUE v_db_args){
  long array_length;
  char** db_args;
  switch(TYPE(v_db_args)){
    case T_STRING:
      db_args = (char **) malloc(2 * sizeof(char *));
      db_args[0] = strdup(StringValueCStr(v_db_args));
      db_args[1] = NULL;
      break;
    case T_ARRAY:
      // Multiple arguments
      array_length = RARRAY_LEN(v_db_args);
      db_args = (char **) malloc((array_length + 1) * sizeof(char *));
      for(long i = 0; i < array_length; ++i){
        VALUE elem = rb_ary_entry(v_db_args, i);
        Check_Type(elem, T_STRING);
        db_args[i] = strdup(StringValueCStr(elem));
      }
      db_args[array_length] = NULL;
      break;
    case T_NIL:
      db_args = NULL;
      break;
    default:
      rb_raise(rb_eTypeError, "Need Single String or Array of Strings for db_args");
  }
  return db_args;
}

/**
 * Free a NULL-terminated array of strings returned by parse_db_args.
 */
static void free_db_args(char** db_args){
  if(!db_args) return;
  for(int i = 0; db_args[i] != NULL; i++)
    free(db_args[i]);
  free(db_args);
}

/**
 * Add parsed db-args to principal entry
 */
void add_db_args(kadm5_principal_ent_rec* entry, char** db_args){
  if (db_args){
    int i;
    for(i = 0; db_args[i] != NULL; i++){
      add_tl_data(&entry->n_tl_data, &entry->tl_data, KRB5_TL_DB_ARGS, strlen(db_args[i]) + 1, (krb5_octet*)db_args[i]);
    }
  }
}

/**
 * Source code taken from kadmin source code at https://github.com/krb5/krb5/blob/master/src/kadmin/cli/kadmin.c
 */
static void free_tl_data(krb5_tl_data *tl){
  while(tl){
    krb5_tl_data *next = tl->tl_data_next;
    free(tl->tl_data_contents);
    free(tl);
    tl = next;
  }
}

void add_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap,
  krb5_int16 tl_type, krb5_ui_2 len, krb5_octet *contents){
  krb5_tl_data* tl_data;
  krb5_octet* copy;

  copy = malloc(len);
  tl_data = calloc(1, sizeof(*tl_data));
  memcpy(copy, contents, len);

  tl_data->tl_data_type = tl_type;
  tl_data->tl_data_length = len;
  tl_data->tl_data_contents = copy;
  tl_data->tl_data_next = NULL;

  // Forward to end of tl_data
  for(; *tl_datap != NULL; tl_datap = &(*tl_datap)->tl_data_next);

  *tl_datap = tl_data;
  (*n_tl_datap)++;
}

void Init_kadm5(void){
  /* The Kadm5 class encapsulates administrative Kerberos functions. */
  cKadm5 = rb_define_class_under(mKerberos, "Kadm5", rb_cObject);

  /* Error typically raised if any of the Kadm5 methods fail. */
  cKadm5Exception = rb_define_class_under(cKadm5, "Exception", rb_eStandardError);

  /* Error raised if a get_principal call cannot find the principal. */
  cKadm5PrincipalNotFoundException = rb_define_class_under(
    cKadm5, "PrincipalNotFoundException", rb_eStandardError
  );

  // Allocation Functions

  rb_define_alloc_func(cKadm5, rkadm5_allocate);

  // Initialization Method

  rb_define_method(cKadm5, "initialize", rkadm5_initialize, 1);

  // Instance Methods

  rb_define_method(cKadm5, "close", rkadm5_close, 0);
  rb_define_method(cKadm5, "create_policy", rkadm5_create_policy, 1);
  rb_define_method(cKadm5, "create_principal", rkadm5_create_principal, -1);
  rb_define_method(cKadm5, "delete_policy", rkadm5_delete_policy, 1);
  rb_define_method(cKadm5, "delete_principal", rkadm5_delete_principal, 1);
  rb_define_method(cKadm5, "find_principal", rkadm5_find_principal, 1);
  rb_define_method(cKadm5, "find_policy", rkadm5_find_policy, 1);
  rb_define_method(cKadm5, "generate_random_key", rkadm5_randkey_principal, 1);
  rb_define_method(cKadm5, "get_policy", rkadm5_get_policy, 1);
  rb_define_method(cKadm5, "get_policies", rkadm5_get_policies, -1);
  rb_define_method(cKadm5, "get_principal", rkadm5_get_principal, 1);
  rb_define_method(cKadm5, "get_principals", rkadm5_get_principals, -1);
  rb_define_method(cKadm5, "get_privileges", rkadm5_get_privs, -1);
  rb_define_method(cKadm5, "modify_policy", rkadm5_modify_policy, 1);
  rb_define_method(cKadm5, "set_password", rkadm5_set_password, 2);
  rb_define_method(cKadm5, "set_pwexpire", rkadm5_set_pwexpire, 2);

  // Constants

  rb_define_const(cKadm5, "DISALLOW_POSTDATED", INT2FIX(KRB5_KDB_DISALLOW_POSTDATED));
  rb_define_const(cKadm5, "DISALLOW_FORWARDABLE", INT2FIX(KRB5_KDB_DISALLOW_FORWARDABLE));
  rb_define_const(cKadm5, "DISALLOW_TGT_BASED", INT2FIX(KRB5_KDB_DISALLOW_TGT_BASED));
  rb_define_const(cKadm5, "DISALLOW_RENEWABLE", INT2FIX(KRB5_KDB_DISALLOW_RENEWABLE));
  rb_define_const(cKadm5, "DISALLOW_PROXIABLE", INT2FIX(KRB5_KDB_DISALLOW_PROXIABLE));
  rb_define_const(cKadm5, "DISALLOW_DUP_SKEY", INT2FIX(KRB5_KDB_DISALLOW_DUP_SKEY));
  rb_define_const(cKadm5, "DISALLOW_ALL_TIX", INT2FIX(KRB5_KDB_DISALLOW_ALL_TIX));
  rb_define_const(cKadm5, "REQUIRES_PRE_AUTH", INT2FIX(KRB5_KDB_REQUIRES_PRE_AUTH));
  rb_define_const(cKadm5, "REQUIRES_HW_AUTH", INT2FIX(KRB5_KDB_REQUIRES_HW_AUTH));
  rb_define_const(cKadm5, "REQUIRES_PWCHANGE", INT2FIX(KRB5_KDB_REQUIRES_PWCHANGE));
  rb_define_const(cKadm5, "DISALLOW_SVR", INT2FIX(KRB5_KDB_DISALLOW_SVR));
  rb_define_const(cKadm5, "PWCHANGE_SERVICE", INT2FIX(KRB5_KDB_PWCHANGE_SERVICE));
  rb_define_const(cKadm5, "SUPPORT_DESMD5", INT2FIX(KRB5_KDB_SUPPORT_DESMD5));
  rb_define_const(cKadm5, "NEW_PRINC", INT2FIX(KRB5_KDB_NEW_PRINC));
}
#endif
