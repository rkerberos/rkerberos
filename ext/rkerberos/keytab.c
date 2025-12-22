#include <rkerberos.h>

VALUE cKrb5Keytab, cKrb5KeytabException;

// Free function for the Kerberos::Krb5::Keytab class.
static void rkrb5_keytab_free(RUBY_KRB5_KEYTAB* ptr){
  if(!ptr)
    return;

  if(ptr->keytab)
    krb5_kt_close(ptr->ctx, ptr->keytab);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Kerberos::Krb5::Keytab class.
static VALUE rkrb5_keytab_allocate(VALUE klass){
  RUBY_KRB5_KEYTAB* ptr = malloc(sizeof(RUBY_KRB5_KEYTAB));
  memset(ptr, 0, sizeof(RUBY_KRB5_KEYTAB));
  return Data_Wrap_Struct(klass, 0, rkrb5_keytab_free, ptr);
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
  VALUE v_kt_entry;
  krb5_error_code kerror;
  krb5_kt_cursor cursor;
  krb5_keytab_entry entry;
  char* principal;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  kerror = krb5_kt_start_seq_get(
    ptr->ctx,
    ptr->keytab,
    &cursor
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));

  while((kerror = krb5_kt_next_entry(ptr->ctx, ptr->keytab, &entry, &cursor)) == 0){
    krb5_unparse_name(ptr->ctx, entry.principal, &principal);

    v_kt_entry = rb_class_new_instance(0, NULL, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    rb_yield(v_kt_entry);

    free(principal);

    krb5_kt_free_entry(ptr->ctx, &entry);
  }

  kerror = krb5_kt_end_seq_get(
    ptr->ctx,
    ptr->keytab,
    &cursor
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));

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

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

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

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;

  return Qtrue;
}

/*
static VALUE rkrb5_keytab_remove_entry(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  krb5_keytab_entry entry;
  char* name;
  VALUE v_name, v_vno, v_enctype;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  rb_scan_args(argc, argv, "12", &v_name, &v_vno, &v_enctype);

  Check_Type(v_name, T_STRING);

  name = StringValueCStr(v_name);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, name, &entry.principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  if(NIL_P(v_vno))
    entry.vno = 0;
  else
    entry.vno = NUM2INT(v_vno);

  if(NIL_P(v_enctype))
    entry.key.enctype = 0;
  else
    entry.key.enctype = NUM2INT(v_enctype);

  entry.key.length = 16;

  kerror = krb5_kt_remove_entry(
    ptr->ctx,
    ptr->keytab,
    &entry
  );

  if(kerror)
    rb_raise(cKrb5KeytabException, "krb5_kt_remove_entry: %s", error_message(kerror));

  return self;
}

static VALUE rkrb5_keytab_add_entry(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  krb5_keytab_entry entry;
  char* name;
  VALUE v_name, v_vno, v_enctype;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  rb_scan_args(argc, argv, "12", &v_name, &v_vno, &v_enctype);

  Check_Type(v_name, T_STRING);

  name = StringValueCStr(v_name);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, name, &entry.principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  if(NIL_P(v_vno))
    entry.vno = 0;
  else
    entry.vno = NUM2INT(v_vno);

  if(NIL_P(v_enctype))
    entry.key.enctype = 0;
  else
    entry.key.enctype = NUM2INT(v_enctype);

  entry.key.length = 16;

  kerror = krb5_kt_add_entry(
    ptr->ctx,
    ptr->keytab,
    &entry
  );

  if(kerror)
    rb_raise(cKrb5KeytabException, "krb5_kt_add_entry: %s", error_message(kerror));

  return self;
}
*/

/*
 * call-seq:
 *   keytab.get_entry(principal, vno = 0, encoding_type = nil)
 *
 * Searches the keytab by +principal+, +vno+ and +encoding_type+. If the
 * +vno+ is zero (the default), then the first entry that matches +principal+
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

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  rb_scan_args(argc, argv, "12", &v_principal, &v_vno, &v_enctype);

  Check_Type(v_principal, T_STRING);
  name = StringValueCStr(v_principal);

  kerror = krb5_parse_name(ptr->ctx, name, &principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_unparse_name: %s", error_message(kerror));

  vno = 0;
  enctype = 0;

  kerror = krb5_kt_get_entry(
    ptr->ctx,
    ptr->keytab,
    principal,
    vno,
    enctype,
    &entry
  );

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
 *   Kerberos::Krb5::Keytab.new(name = nil)
 *
 * Creates and returns a new Kerberos::Krb5::Keytab object. This initializes
 * the context and keytab for future method calls on that object.
 *
 * A keytab file +name+ may be provided. If not, the system's default keytab
 * name is used. If a +name+ is provided it must be in the form 'type:residual'
 * where 'type' is a type known to the Kerberos library.
 *
 * Examples:
 *
 *   # Using the default keytab
 *   keytab = Kerberos::Krb5::Keytab.new
 *
 *   # Using an explicit keytab
 *   keytab = Kerberos::Krb5::Keytab.new('FILE:/etc/krb5.keytab')
 */
static VALUE rkrb5_keytab_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  char keytab_name[MAX_KEYTAB_NAME_LEN];
  VALUE v_keytab_name = Qnil;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  rb_scan_args(argc, argv, "01", &v_keytab_name);

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(ptr->ctx, keytab_name, MAX_KEYTAB_NAME_LEN);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

    rb_iv_set(self, "@name", rb_str_new2(keytab_name));
  }
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValueCStr(v_keytab_name), MAX_KEYTAB_NAME_LEN);
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
  VALUE v_kt_entry;
  VALUE v_keytab_name;
  krb5_error_code kerror;
  krb5_kt_cursor cursor;
  krb5_keytab keytab;
  krb5_keytab_entry entry;
  krb5_context context;
  char* principal;
  char keytab_name[MAX_KEYTAB_NAME_LEN];

  rb_scan_args(argc, argv, "01", &v_keytab_name);

  kerror = krb5_init_context(&context);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(context, keytab_name, MAX_KEYTAB_NAME_LEN);

    if(kerror){
      if(context)
        krb5_free_context(context);

      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));
    }
  }
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValueCStr(v_keytab_name), MAX_KEYTAB_NAME_LEN);
  }

  kerror = krb5_kt_resolve(
    context,
    keytab_name,
    &keytab
  );

  if(kerror){
    if(context)
      krb5_free_context(context);

    rb_raise(cKrb5Exception, "krb5_kt_resolve: %s", error_message(kerror));
  }

  kerror = krb5_kt_start_seq_get(
    context,
    keytab,
    &cursor
  );

  if(kerror){
    if(context)
      krb5_free_context(context);

    if(keytab)
      krb5_kt_close(context, keytab);

    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));
  }

  while((kerror = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
    krb5_unparse_name(context, entry.principal, &principal);

    v_kt_entry = rb_class_new_instance(0, NULL, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    rb_yield(v_kt_entry);

    free(principal);

    krb5_kt_free_entry(context, &entry);
  }

  kerror = krb5_kt_end_seq_get(
    context,
    keytab,
    &cursor
  );

  if(kerror){
    if(context)
      krb5_free_context(context);

    if(keytab)
      krb5_kt_close(context, keytab);

    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));
  }

  if(keytab)
    krb5_kt_close(context, keytab);

  if(context)
    krb5_free_context(context);

  return Qnil;
}

void Init_keytab(){
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

  // TODO: Move these into Kadm5 and/or figure out how to set the vno properly.
  // rb_define_method(cKrb5Keytab, "add_entry", rkrb5_keytab_add_entry, -1);
  // rb_define_method(cKrb5Keytab, "remove_entry", rkrb5_keytab_remove_entry, -1);

  // Accessors

  /* The name of the keytab associated with the current keytab object. */
  rb_define_attr(cKrb5Keytab, "name", 1, 0);

  // Aliases

  rb_define_alias(cKrb5Keytab, "find", "get_entry");
}
