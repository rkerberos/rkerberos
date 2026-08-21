#include <rkerberos.h>

VALUE cKrb5Keytab, cKrb5KeytabException;


// TypedData functions for RUBY_KRB5_KEYTAB
static void rkrb5_keytab_typed_mark(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_KEYTAB *kt = (RUBY_KRB5_KEYTAB *)ptr;
  if (kt->rb_context != Qnil)
    rb_gc_mark(kt->rb_context);
}

void rkrb5_keytab_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KRB5_KEYTAB *kt = (RUBY_KRB5_KEYTAB *)ptr;
  if (kt->keytab && kt->ctx)
    krb5_kt_close(kt->ctx, kt->keytab);
  if (kt->ctx)
    krb5_free_cred_contents(kt->ctx, &kt->creds);
  if (kt->ctx && kt->rb_context == Qnil)
    krb5_free_context(kt->ctx);
  free(kt);
}

size_t rkrb5_keytab_typed_size(const void *ptr) {
  return sizeof(RUBY_KRB5_KEYTAB);
}

// Must NOT be static so it is exported
const rb_data_type_t rkrb5_keytab_data_type = {
  "RUBY_KRB5_KEYTAB",
  {rkrb5_keytab_typed_mark, rkrb5_keytab_typed_free, rkrb5_keytab_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

VALUE rkrb5_keytab_allocate(VALUE klass){
  RUBY_KRB5_KEYTAB* ptr = ALLOC(RUBY_KRB5_KEYTAB);
  memset(ptr, 0, sizeof(RUBY_KRB5_KEYTAB));
  ptr->rb_context = Qnil;
  return TypedData_Wrap_Struct(klass, &rkrb5_keytab_data_type, ptr);
}

// Allocation function for the Kerberos::Krb5::Keytab class.

// Struct for rb_ensure in each()
typedef struct {
  krb5_context ctx;
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  int cursor_active;
} keytab_each_arg;

static VALUE rkrb5_keytab_each_body(VALUE arg){
  keytab_each_arg* ea = (keytab_each_arg*)arg;
  krb5_keytab_entry entry;
  krb5_error_code kerror;
  char* principal;
  VALUE v_kt_entry;

  while((kerror = krb5_kt_next_entry(ea->ctx, ea->keytab, &entry, &ea->cursor)) == 0){
    kerror = krb5_unparse_name(ea->ctx, entry.principal, &principal);

    if(kerror){
      krb5_kt_free_entry(ea->ctx, &entry);
      rb_raise(cKrb5Exception, "krb5_unparse_name: %s", error_message(kerror));
    }

    v_kt_entry = rb_class_new_instance(0, NULL, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    krb5_free_unparsed_name(ea->ctx, principal);
    krb5_kt_free_entry(ea->ctx, &entry);

    rb_yield(v_kt_entry);
  }

  ea->cursor_active = 0;

  kerror = krb5_kt_end_seq_get(ea->ctx, ea->keytab, &ea->cursor);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));

  return Qnil;
}

static VALUE rkrb5_keytab_each_ensure(VALUE arg){
  keytab_each_arg* ea = (keytab_each_arg*)arg;

  if(ea->cursor_active)
    krb5_kt_end_seq_get(ea->ctx, ea->keytab, &ea->cursor);

  return Qnil;
}

/*
 * call-seq:
 *
 *   keytab.each{ |entry| p entry }
 *
 * Iterates over each entry, and yield the principal name.
 *--
 * TODO: Mixin Enumerable properly.
 */
static VALUE rkrb5_keytab_each(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  keytab_each_arg ea;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx || !ptr->keytab)
    rb_raise(cKrb5Exception, "keytab is closed");

  ea.ctx = ptr->ctx;
  ea.keytab = ptr->keytab;

  kerror = krb5_kt_start_seq_get(ea.ctx, ea.keytab, &ea.cursor);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));

  ea.cursor_active = 1;

  rb_ensure(rkrb5_keytab_each_body, (VALUE)&ea, rkrb5_keytab_each_ensure, (VALUE)&ea);

  return self;
}

/*
 * call-seq:
 *
 *   keytab.default_name
 *
 * Returns the default keytab name.
 */
static VALUE rkrb5_keytab_default_name(VALUE self){
  char default_name[MAX_KEYTAB_NAME_LEN];
  krb5_error_code kerror;
  RUBY_KRB5_KEYTAB* ptr;
  VALUE v_default_name;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_kt_default_name(ptr->ctx, default_name, MAX_KEYTAB_NAME_LEN);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

  v_default_name = rb_str_new2(default_name);

  return v_default_name;
}

/*
 * call-seq:
 *   keytab.close
 *
 * Close the keytab object. Internally this frees up any associated
 * credential contents and the Kerberos context. Once a keytab object
 * is closed it cannot be reused.
 */
static VALUE rkrb5_keytab_close(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(ptr->keytab && ptr->ctx){
    krb5_kt_close(ptr->ctx, ptr->keytab);
    ptr->keytab = NULL;
  }

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->ctx && ptr->rb_context == Qnil)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;
  ptr->rb_context = Qnil;

  return Qtrue;
}

/*
 * call-seq:
 *   keytab.add_entry(principal:, password:, vno: 1, enctype: 18)
 *
 * Add a new entry to the keytab for the given +principal+ string.
 *
 * A key is derived from +password+ (and the principal-based salt) using
 * +krb5_c_string_to_key+, so the resulting key will match what the KDC
 * would generate for the same password.
 *
 * Options:
 *   principal:: A Kerberos principal name string (required).
 *   password::  The password used to derive the key (required).
 *   vno::       Key version number (default 1).
 *   enctype::   Encryption type as an integer (default 18,
 *               aes256-cts-hmac-sha1-96).
 *
 * Returns +self+.
 */
static VALUE rkrb5_keytab_add_entry(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  krb5_keytab_entry entry;
  krb5_data pwd_data, salt;
  VALUE v_opts, v_principal, v_password, v_vno, v_enctype;
  ID kw_table[4] = { rb_intern("principal"), rb_intern("password"), rb_intern("vno"), rb_intern("enctype") };
  VALUE kw_vals[4];

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    v_opts = rb_hash_new();

  rb_get_kwargs(v_opts, kw_table, 2, 2, kw_vals);
  v_principal = kw_vals[0];
  v_password = kw_vals[1];
  v_vno = kw_vals[2] == Qundef ? Qnil : kw_vals[2];
  v_enctype = kw_vals[3] == Qundef ? Qnil : kw_vals[3];

  Check_Type(v_principal, T_STRING);
  Check_Type(v_password, T_STRING);

  memset(&entry, 0, sizeof(entry));

  entry.vno = NIL_P(v_vno) ? 1 : NUM2INT(v_vno);
  entry.key.enctype = NIL_P(v_enctype) ? ENCTYPE_AES256_CTS_HMAC_SHA1_96 : NUM2INT(v_enctype);

  kerror = krb5_parse_name(ptr->ctx, StringValueCStr(v_principal), &entry.principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  entry.timestamp = time(NULL);

  // Derive the salt from the principal
  kerror = krb5_principal2salt(ptr->ctx, entry.principal, &salt);

  if(kerror){
    krb5_free_principal(ptr->ctx, entry.principal);
    rb_raise(cKrb5Exception, "krb5_principal2salt: %s", error_message(kerror));
  }

  // Derive key from password + salt
  pwd_data.data   = StringValuePtr(v_password);
  pwd_data.length = (unsigned int)RSTRING_LEN(v_password);

  kerror = krb5_c_string_to_key(ptr->ctx, entry.key.enctype, &pwd_data, &salt, &entry.key);

  krb5_free_data_contents(ptr->ctx, &salt);

  if(kerror){
    krb5_free_principal(ptr->ctx, entry.principal);
    rb_raise(cKrb5Exception, "krb5_c_string_to_key: %s", error_message(kerror));
  }

  kerror = krb5_kt_add_entry(ptr->ctx, ptr->keytab, &entry);

  krb5_free_keyblock_contents(ptr->ctx, &entry.key);
  krb5_free_principal(ptr->ctx, entry.principal);

  if(kerror)
    rb_raise(cKrb5KeytabException, "krb5_kt_add_entry: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   keytab.remove_entry(principal:, vno: 0, enctype: 0)
 *
 * Remove entries from the keytab that match the given +principal+ string,
 * +vno+, and +enctype+.
 *
 * A +vno+ of 0 (the default) matches any version number.
 * An +enctype+ of 0 (the default) matches any encryption type.
 *
 * When both +vno+ and +enctype+ are 0 (the defaults), all entries for
 * the +principal+ are removed.
 *
 * Options:
 *   principal:: A Kerberos principal name string (required).
 *   vno::       Key version number to match, 0 for any (default 0).
 *   enctype::   Encryption type to match, 0 for any (default 0).
 *
 * Returns +self+.
 */
static VALUE rkrb5_keytab_remove_entry(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  krb5_keytab_entry found_entry;
  krb5_principal match_princ;
  krb5_kvno match_vno;
  krb5_enctype match_enctype;
  int removed = 0;
  VALUE v_opts, v_principal, v_vno, v_enctype;
  ID kw_table[3] = { rb_intern("principal"), rb_intern("vno"), rb_intern("enctype") };
  VALUE kw_vals[3];

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    v_opts = rb_hash_new();

  rb_get_kwargs(v_opts, kw_table, 1, 2, kw_vals);
  v_principal = kw_vals[0];
  v_vno = kw_vals[1] == Qundef ? Qnil : kw_vals[1];
  v_enctype = kw_vals[2] == Qundef ? Qnil : kw_vals[2];

  Check_Type(v_principal, T_STRING);

  match_vno = NIL_P(v_vno) ? 0 : NUM2INT(v_vno);
  match_enctype = NIL_P(v_enctype) ? 0 : NUM2INT(v_enctype);

  kerror = krb5_parse_name(ptr->ctx, StringValueCStr(v_principal), &match_princ);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  // Retrieve the full entry via krb5_kt_get_entry and then pass the
  // complete struct to krb5_kt_remove_entry so all fields match exactly.
  // Loop to remove every matching entry when vno/enctype are wildcards.
  while(1){
    kerror = krb5_kt_get_entry(
      ptr->ctx, ptr->keytab, match_princ,
      match_vno, match_enctype, &found_entry
    );

    if(kerror){
      krb5_free_principal(ptr->ctx, match_princ);
      if(removed)
        return self;
      rb_raise(cKrb5KeytabException, "krb5_kt_remove_entry: %s", error_message(kerror));
    }

    kerror = krb5_kt_remove_entry(ptr->ctx, ptr->keytab, &found_entry);
    krb5_kt_free_entry(ptr->ctx, &found_entry);

    if(kerror){
      krb5_free_principal(ptr->ctx, match_princ);
      rb_raise(cKrb5KeytabException, "krb5_kt_remove_entry: %s", error_message(kerror));
    }

    removed = 1;
  }
}

/*
 * call-seq:
 *   keytab.get_entry(principal, vno = 0, encoding_type = nil)
 *
 * Searches the keytab by +principal+, +vno+ (version number) and +encoding_type+.
 * If the +vno+ is zero (the default), then the first entry that matches +principal+
 * is returned.
 *
 * Returns a Kerberos::Krb5::KeytabEntry object if the entry is found.
 *
 * Raises an exception if no entry is found.
 */
static VALUE rkrb5_keytab_get_entry(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  krb5_principal principal;
  krb5_kvno vno;
  krb5_enctype enctype;
  krb5_keytab_entry entry;
  char* name;
  VALUE v_principal, v_vno, v_enctype, v_entry;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx || !ptr->keytab)
    rb_raise(cKrb5Exception, "keytab is closed");

  rb_scan_args(argc, argv, "12", &v_principal, &v_vno, &v_enctype);

  Check_Type(v_principal, T_STRING);
  name = StringValueCStr(v_principal);

  vno = NIL_P(v_vno) ? 0 : NUM2INT(v_vno);
  enctype = NIL_P(v_enctype) ? 0 : NUM2INT(v_enctype);

  kerror = krb5_parse_name(ptr->ctx, name, &principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = krb5_kt_get_entry(
    ptr->ctx,
    ptr->keytab,
    principal,
    vno,
    enctype,
    &entry
  );

  krb5_free_principal(ptr->ctx, principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_get_entry: %s", error_message(kerror));

  v_entry = rb_class_new_instance(0, NULL, cKrb5KtEntry);

  rb_iv_set(v_entry, "@principal", rb_str_new2(name));
  rb_iv_set(v_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
  rb_iv_set(v_entry, "@vno", INT2FIX(entry.vno));
  rb_iv_set(v_entry, "@key", INT2FIX(entry.key.enctype));

  krb5_kt_free_entry(ptr->ctx, &entry);

  return v_entry;
}

/*
 * call-seq:
 *   keytab.keytab_name
 *
 * Return the name associated with the open keytab. This returns the canonical
 * type:residual string used internally by the library. It will usually be the
 * same as the +name+ method, but could be different.
 */
static VALUE rkrb5_keytab_get_name(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  char name[MAX_KEYTAB_NAME_LEN];

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_kt_get_name(ptr->ctx, ptr->keytab, name, MAX_KEYTAB_NAME_LEN);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_get_name: %s", error_message(kerror));

  return rb_str_new2(name);
}

/*
 * call-seq:
 *   keytab.keytab_type
 *
 * Return the keytab type portion, e.g. "FILE". Raises an error if nil.
 */
static VALUE rkrb5_keytab_get_type(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  const char *type;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  type = krb5_kt_get_type(ptr->ctx, ptr->keytab);

  if(!type)
    rb_raise(cKrb5Exception, "krb5_kt_get_type returned NULL");

  return rb_str_new2(type);
}

/*
 * call-seq:
 *   keytab.dup -> new_keytab
 *
 * Duplicate the keytab object so that both handles may be closed
 * independently.  Underlying data is shared by the krb5 library; the
 * new Ruby object receives a fresh context.
 */
static VALUE rkrb5_keytab_dup(VALUE self){
  RUBY_KRB5_KEYTAB *ptr, *newptr;
  krb5_error_code kerror;
  VALUE newobj;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  newobj = rkrb5_keytab_allocate(CLASS_OF(self));
  TypedData_Get_Struct(newobj, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, newptr);

  kerror = krb5_init_context(&newptr->ctx);
  if(kerror){
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));
  }

  kerror = krb5_kt_dup(newptr->ctx, ptr->keytab, &newptr->keytab);
  if(kerror){
    krb5_free_context(newptr->ctx);
    newptr->ctx = NULL;
    rb_raise(cKrb5Exception, "krb5_kt_dup: %s", error_message(kerror));
  }

  rb_iv_set(newobj, "@name", rb_iv_get(self, "@name"));

  return newobj;
}

/*
 * call-seq:
 *   Kerberos::Krb5::Keytab.new(name: nil, context: nil)
 *
 * Creates and returns a new Kerberos::Krb5::Keytab object. This initializes
 * the context and keytab for future method calls on that object.
 *
 * A keytab file +name+ may be provided. If not, the system's default keytab
 * name is used. If a +name+ is provided it must be in the form 'type:residual'
 * where 'type' is a type known to the Kerberos library.
 *
 * An optional +context+ keyword argument may be provided. If given, it must
 * be a Kerberos::Krb5::Context object and will be used instead of creating
 * a new context via krb5_init_context.
 *
 * Examples:
 *
 *   # Using the default keytab
 *   keytab = Kerberos::Krb5::Keytab.new
 *
 *   # Using an explicit keytab
 *   keytab = Kerberos::Krb5::Keytab.new(name: 'FILE:/etc/krb5.keytab')
 *
 *   # Using a custom context
 *   ctx = Kerberos::Krb5::Context.new
 *   keytab = Kerberos::Krb5::Keytab.new(name: 'FILE:/etc/krb5.keytab', context: ctx)
 */
static VALUE rkrb5_keytab_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  char keytab_name[MAX_KEYTAB_NAME_LEN];
  VALUE v_keytab_name = Qnil;
  VALUE v_opts = Qnil;
  VALUE v_context = Qnil;
  ID kw_table[2] = { rb_intern("name"), rb_intern("context") };
  VALUE kw_vals[2];

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_opts);

  if(NIL_P(v_opts))
    v_opts = rb_hash_new();

  rb_get_kwargs(v_opts, kw_table, 0, 2, kw_vals);
  v_keytab_name = kw_vals[0] == Qundef ? Qnil : kw_vals[0];
  v_context = kw_vals[1] == Qundef ? Qnil : kw_vals[1];

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

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(ptr->ctx, keytab_name, MAX_KEYTAB_NAME_LEN);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

    rb_iv_set(self, "@name", rb_str_new2(keytab_name));
  }
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValueCStr(v_keytab_name), MAX_KEYTAB_NAME_LEN - 1);
    keytab_name[MAX_KEYTAB_NAME_LEN - 1] = '\0';
    rb_iv_set(self, "@name", v_keytab_name);
  }

  kerror = krb5_kt_resolve(
    ptr->ctx,
    keytab_name,
    &ptr->keytab
  );

  if(kerror)
    rb_raise(cKrb5KeytabException, "krb5_kt_resolve: %s", error_message(kerror));

  return self;
}

// Singleton Methods

// Struct for rb_ensure in foreach()
typedef struct {
  krb5_context ctx;
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  int cursor_active;
} keytab_foreach_arg;

static VALUE rkrb5_s_keytab_foreach_body(VALUE arg){
  keytab_foreach_arg* fa = (keytab_foreach_arg*)arg;
  krb5_keytab_entry entry;
  krb5_error_code kerror;
  char* principal;
  VALUE v_kt_entry;

  while((kerror = krb5_kt_next_entry(fa->ctx, fa->keytab, &entry, &fa->cursor)) == 0){
    kerror = krb5_unparse_name(fa->ctx, entry.principal, &principal);

    if(kerror){
      krb5_kt_free_entry(fa->ctx, &entry);
      rb_raise(cKrb5Exception, "krb5_unparse_name: %s", error_message(kerror));
    }

    v_kt_entry = rb_class_new_instance(0, NULL, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    krb5_free_unparsed_name(fa->ctx, principal);
    krb5_kt_free_entry(fa->ctx, &entry);

    rb_yield(v_kt_entry);
  }

  fa->cursor_active = 0;

  kerror = krb5_kt_end_seq_get(fa->ctx, fa->keytab, &fa->cursor);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));

  return Qnil;
}

static VALUE rkrb5_s_keytab_foreach_ensure(VALUE arg){
  keytab_foreach_arg* fa = (keytab_foreach_arg*)arg;

  if(fa->cursor_active)
    krb5_kt_end_seq_get(fa->ctx, fa->keytab, &fa->cursor);

  if(fa->keytab)
    krb5_kt_close(fa->ctx, fa->keytab);

  if(fa->ctx)
    krb5_free_context(fa->ctx);

  return Qnil;
}

/*
 * call-seq:
 *   Kerberos::Krb5::Keytab.foreach(keytab = nil){ |entry|
 *     puts entry.inspect
 *   }
 *
 * Iterate over each entry in the +keytab+ and yield a Krb5::Keytab::Entry
 * object for each entry found.
 *
 * If no +keytab+ is provided, then the default keytab is used.
 */
static VALUE rkrb5_s_keytab_foreach(int argc, VALUE* argv, VALUE klass){
  VALUE v_keytab_name;
  krb5_error_code kerror;
  keytab_foreach_arg fa;
  char keytab_name[MAX_KEYTAB_NAME_LEN];

  memset(&fa, 0, sizeof(fa));

  rb_scan_args(argc, argv, "01", &v_keytab_name);

  kerror = krb5_init_context(&fa.ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(fa.ctx, keytab_name, MAX_KEYTAB_NAME_LEN);

    if(kerror){
      krb5_free_context(fa.ctx);
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));
    }
  }
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValueCStr(v_keytab_name), MAX_KEYTAB_NAME_LEN - 1);
    keytab_name[MAX_KEYTAB_NAME_LEN - 1] = '\0';
  }

  kerror = krb5_kt_resolve(fa.ctx, keytab_name, &fa.keytab);

  if(kerror){
    krb5_free_context(fa.ctx);
    rb_raise(cKrb5Exception, "krb5_kt_resolve: %s", error_message(kerror));
  }

  kerror = krb5_kt_start_seq_get(fa.ctx, fa.keytab, &fa.cursor);

  if(kerror){
    krb5_kt_close(fa.ctx, fa.keytab);
    krb5_free_context(fa.ctx);
    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));
  }

  fa.cursor_active = 1;

  rb_ensure(rkrb5_s_keytab_foreach_body, (VALUE)&fa, rkrb5_s_keytab_foreach_ensure, (VALUE)&fa);

  return Qnil;
}

/*
 * call-seq:
 *   keytab.have_content? -> true or false
 *
 * Returns true if the keytab exists and contains entries, false otherwise.
 */
static VALUE rkrb5_keytab_have_content(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KRB5_KEYTAB, &rkrb5_keytab_data_type, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_kt_have_content(ptr->ctx, ptr->keytab);

  return kerror ? Qfalse : Qtrue;
}

void Init_keytab(void){
  /* The Kerberos::Krb5::Keytab class encapsulates a Kerberos keytab. */
  cKrb5Keytab = rb_define_class_under(cKrb5, "Keytab", rb_cObject);

  /* The Keytab::Exception is typically raised if any of the Keytab methods fail. */
  cKrb5KeytabException = rb_define_class_under(cKrb5Keytab, "Exception", rb_eStandardError);

  // Allocation Function

  rb_define_alloc_func(cKrb5Keytab, rkrb5_keytab_allocate);

  // Constructor

  rb_define_method(cKrb5Keytab, "initialize", rkrb5_keytab_initialize, -1);

  // Singleton Methods

  rb_define_singleton_method(cKrb5Keytab, "foreach", rkrb5_s_keytab_foreach, -1);

  // Instance Methods

  rb_define_method(cKrb5Keytab, "default_name", rkrb5_keytab_default_name, 0);
  rb_define_method(cKrb5Keytab, "close", rkrb5_keytab_close, 0);
  rb_define_method(cKrb5Keytab, "each", rkrb5_keytab_each, 0);
  rb_define_method(cKrb5Keytab, "get_entry", rkrb5_keytab_get_entry, -1);
  rb_define_method(cKrb5Keytab, "keytab_name", rkrb5_keytab_get_name, 0);
  rb_define_method(cKrb5Keytab, "keytab_type", rkrb5_keytab_get_type, 0);
  rb_define_method(cKrb5Keytab, "dup", rkrb5_keytab_dup, 0);
  rb_define_method(cKrb5Keytab, "have_content?", rkrb5_keytab_have_content, 0);
  rb_define_alias(cKrb5Keytab, "clone", "dup");

  rb_define_method(cKrb5Keytab, "add_entry", rkrb5_keytab_add_entry, -1);
  rb_define_method(cKrb5Keytab, "remove_entry", rkrb5_keytab_remove_entry, -1);

  // Accessors

  /* The name of the keytab associated with the current keytab object. */
  rb_define_attr(cKrb5Keytab, "name", 1, 0);

  // Aliases

  rb_define_alias(cKrb5Keytab, "find", "get_entry");
}
