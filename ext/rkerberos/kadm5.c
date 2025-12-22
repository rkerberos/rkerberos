#include <rkerberos.h>
#include <kdb.h>

VALUE cKadm5;
VALUE cKadm5Exception;
VALUE cKadm5PrincipalNotFoundException;

// Prototype
static VALUE rkadm5_close(VALUE);
char** parse_db_args(VALUE v_db_args);
void add_db_args(kadm5_principal_ent_rec*, char**);
void add_tl_data(krb5_int16 *, krb5_tl_data **,
  krb5_int16, krb5_ui_2, krb5_octet *);

// Free function for the Kerberos::Kadm5 class.
static void rkadm5_free(RUBY_KADM5* ptr){
  if(!ptr)
    return;

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr->db_args);
  free(ptr);
}

const rb_data_type_t kadm5_type = {
  .wrap_struct_name = "kadm5",
  .function = {
    .dfree = (void (*)(void*))rkadm5_free,
    .dsize = NULL,
    .dmark = NULL,
  },
  .data = NULL,
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Kadm5 class.
static VALUE rkadm5_allocate(VALUE klass){
  RUBY_KADM5* ptr = malloc(sizeof(RUBY_KADM5));
  memset(ptr, 0, sizeof(RUBY_KADM5));
  return TypedData_Wrap_Struct(klass, &kadm5_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::Kadm5.new(:principal => 'name', :password => 'xxxxx')
 *   Kerberos::Kadm5.new(:principal => 'name', :keytab => '/path/to/your/keytab')
 *   Kerberos::Kadm5.new(:principal => 'name', :keytab => true)
 *
 * Creates and returns a new Kerberos::Kadm5 object. A hash argument is
 * accepted that allows you to specify a principal and a password, or
 * a keytab file.
 *
 * If you pass a string as the :keytab value it will attempt to use that file
 * for the keytab. If you pass true as the value it will attempt to use the
 * default keytab file, typically /etc/krb5.keytab.
 *
 * You may also pass the :service option to specify the service name. The
 * default is kadmin/admin.
 *
 * There is also a :db_args option, which is a single string or array of strings
 * containing options usually passed to kadmin with the -x switch. For a list of
 * available options, see the kadmin manpage
 *
 */
static VALUE rkadm5_initialize(VALUE self, VALUE v_opts){
  RUBY_KADM5* ptr;
  VALUE v_principal, v_password, v_keytab, v_service, v_db_args;
  char* user;
  char* pass = NULL;
  char* keytab = NULL;
  char* service = NULL;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  Check_Type(v_opts, T_HASH);

  v_principal = rb_hash_aref2(v_opts, "principal");

  // Principal must be specified
  if(NIL_P(v_principal))
    rb_raise(rb_eArgError, "principal must be specified");

  Check_Type(v_principal, T_STRING);
  user = StringValueCStr(v_principal);

  v_password = rb_hash_aref2(v_opts, "password");
  v_keytab = rb_hash_aref2(v_opts, "keytab");

  if(RTEST(v_password) && RTEST(v_keytab))
    rb_raise(rb_eArgError, "cannot use both a password and a keytab");

  if(RTEST(v_password)){
    Check_Type(v_password, T_STRING);
    pass = StringValueCStr(v_password);
  }

  v_service = rb_hash_aref2(v_opts, "service");

  if(NIL_P(v_service)){
    service = (char *) "kadmin/admin";
  }
  else{
    Check_Type(v_service, T_STRING);
    service = StringValueCStr(v_service);
  }

  v_db_args = rb_hash_aref2(v_opts, "db_args");
  ptr->db_args = parse_db_args(v_db_args);

  // Normally I would wait to initialize the context, but we might need it
  // to get the default keytab file name.
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_init_context: %s", error_message(kerror));

  // The docs say I can use NULL to get the default, but reality appears to be otherwise.
  if(RTEST(v_keytab)){
    if(TYPE(v_keytab) == T_TRUE){
      char default_name[MAX_KEYTAB_NAME_LEN];

      kerror = krb5_kt_default_name(ptr->ctx, default_name, MAX_KEYTAB_NAME_LEN);

      if(kerror)
        rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

      keytab = default_name;
    }
    else{
      Check_Type(v_keytab, T_STRING);
      keytab = StringValueCStr(v_keytab);
    }
  }

  if(RTEST(v_password)){
#ifdef KADM5_API_VERSION_3
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
#else
    kerror = kadm5_init_with_password(
      user,
      pass,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_2,
      ptr->db_args,
      &ptr->handle
    );
#endif

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_password: %s", error_message(kerror));
  }
  else if(RTEST(v_keytab)){
#ifdef KADM5_API_VERSION_3
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
#else
    kerror = kadm5_init_with_skey(
      user,
      keytab,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_2,
      ptr->db_args,
      &ptr->handle
    );
#endif

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_skey: %s", error_message(kerror));
  }
  else{
    // TODO: Credentials cache.
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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  user = StringValueCStr(v_user);
  pass = StringValueCStr(v_pass);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_chpass_principal(ptr->handle, ptr->princ, pass);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_chpass_principal: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   kadm5.create_principal(name, password, db_args=nil)
 *   kadm5.create_principal(principal)
 *
 * Creates a new principal +name+ with an initial password of +password+.
 * +db_args+ is an optional string or array of strings containing options that are usually
 * passed to add_principal with the -x option. For a list of options, see the kadmin manpage,
 * in the add_principal section.
 *--
 * TODO: Allow a Principal object to be passed in as an argument.
 */
static VALUE rkadm5_create_principal(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  char* user;
  char* pass;
  char** db_args;
  int mask;
  kadm5_principal_ent_rec princ;
  krb5_error_code kerror;
  VALUE v_user, v_pass, v_db_args;

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

  rb_scan_args(argc, argv, "21", &v_user, &v_pass, &v_db_args);
  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  memset(&princ, 0, sizeof(princ));

  mask = KADM5_PRINCIPAL | KADM5_TL_DATA;
  user = StringValueCStr(v_user);
  pass = StringValueCStr(v_pass);

  db_args = parse_db_args(v_db_args);
  add_db_args(&princ, db_args);
  free(db_args);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &princ.principal);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_create_principal(ptr->handle, &princ, mask, pass);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_create_principal: %s", error_message(kerror));

  krb5_free_principal(ptr->ctx, princ.principal);

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

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
  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  if(ptr->handle)
    kadm5_destroy(ptr->handle);

  free(ptr->db_args);

  ptr->db_args = NULL;
  ptr->ctx    = NULL;
  ptr->princ  = NULL;
  ptr->handle = NULL;

  return self;
}

// Private function for creating a Principal object from a entry record.
static VALUE create_principal_from_entry(VALUE v_name, RUBY_KADM5* ptr, kadm5_principal_ent_rec* ent){
  krb5_error_code kerror;
  VALUE v_principal;
  VALUE v_args[1];

  v_args[0] = v_name;

  v_principal = rb_class_new_instance(1, v_args, cKrb5Principal);

  rb_iv_set(v_principal, "@attributes", LONG2FIX(ent->attributes));
  rb_iv_set(v_principal, "@aux_attributes", INT2FIX(ent->aux_attributes));

  if(ent->princ_expire_time)
    rb_iv_set(v_principal, "@expire_time", rb_time_new(ent->princ_expire_time, 0));

  rb_iv_set(v_principal, "@fail_auth_count", INT2FIX(ent->fail_auth_count));
  rb_iv_set(v_principal, "@kvno", INT2FIX(ent->kvno));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_failed", rb_time_new(ent->last_failed, 0));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_password_change", rb_time_new(ent->last_pwd_change, 0));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_success", rb_time_new(ent->last_success, 0));

  rb_iv_set(v_principal, "@max_life", LONG2FIX(ent->max_life));
  rb_iv_set(v_principal, "@max_renewable_life", LONG2FIX(ent->max_renewable_life));

  if(ent->mod_date)
    rb_iv_set(v_principal, "@mod_date", rb_time_new(ent->mod_date, 0));

  if(ent->mod_name){
    char* mod_name;
    kerror = krb5_unparse_name(ptr->ctx, ent->mod_name, &mod_name);

    if(kerror)
      rb_raise(cKadm5Exception, "krb5_unparse_name: %s", error_message(kerror));

    rb_iv_set(v_principal, "@mod_name", rb_str_new2(mod_name));
  }

  if(ent->pw_expiration)
    rb_iv_set(v_principal, "@password_expiration", rb_time_new(ent->pw_expiration, 0));

  if(ent->policy)
    rb_iv_set(v_principal, "policy", rb_str_new2(ent->policy));

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValueCStr(v_user);

  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

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
    ent.pw_max_life = NUM2LONG(v_history_num);
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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);
  TypedData_Get_Struct(v_policy, RUBY_KADM5_POLICY, &kadm5_policy_type, pptr);

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

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
 */
static VALUE rkadm5_get_privs(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5* ptr;
  VALUE v_return = Qnil;
  VALUE v_strings = Qfalse;
  kadm5_ret_t kerror;
  unsigned int i;
  long privs;
  int result = 0;

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

  rb_scan_args(argc, argv, "01", &v_strings);

  kerror = kadm5_get_privs(ptr->handle, &privs);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_get_privs: %s (%li)", error_message(kerror), kerror);

  if(RTEST(v_strings)){
    v_return = rb_ary_new();

    for(i = 0; i < sizeof(privs); i++){
      result |= (privs & 1 << i);
      switch(privs & 1 << i){
        case KADM5_PRIV_GET:
          rb_ary_push(v_return, rb_str_new2("GET"));
          break;
        case KADM5_PRIV_ADD:
          rb_ary_push(v_return, rb_str_new2("ADD"));
          break;
        case KADM5_PRIV_MODIFY:
          rb_ary_push(v_return, rb_str_new2("MODIFY"));
          break;
        case KADM5_PRIV_DELETE:
          rb_ary_push(v_return, rb_str_new2("DELETE"));
          break;
        default:
          rb_ary_push(v_return, rb_str_new2("UNKNOWN"));
      };
    }
  }
  else{
    for(i = 0; i < sizeof(privs); i++){
      result |= (privs & 1 << i);
    }
    v_return = INT2FIX(result);
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

  TypedData_Get_Struct(self, RUBY_KADM5, &kadm5_type, ptr);

  user = StringValueCStr(v_user);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_randkey_principal(ptr->handle, princ, &keys, &n_keys);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_randkey_principal: %s (%li)", error_message(kerror), kerror);

  for(i = 0; i < n_keys; i++)
    krb5_free_keyblock_contents(ptr->ctx, &keys[i]);

  free(keys);

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
      db_args[0] = StringValueCStr(v_db_args);
      db_args[1] = NULL;
      break;
    case T_ARRAY:
      // Multiple arguments
      array_length = RARRAY_LEN(v_db_args);
      db_args = (char **) malloc(array_length * sizeof(char *) + 1);
      for(long i = 0; i < array_length; ++i){
        VALUE elem = rb_ary_entry(v_db_args, i);
        Check_Type(elem, T_STRING);
        db_args[i] = StringValueCStr(elem);
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

void Init_kadm5(){
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
