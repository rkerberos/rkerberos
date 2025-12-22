#include <rkerberos.h>

VALUE cKrb5KtEntry;

// Free function for the Kerberos::Krb5::Keytab::Entry class.
static void rkrb5_kt_entry_free(RUBY_KRB5_KT_ENTRY* ptr){
  if(!ptr)
    return;

  free(ptr);
}

// Allocation function for the Kerberos::Krb5::Keytab::Entry class.
static VALUE rkrb5_kt_entry_allocate(VALUE klass){
  RUBY_KRB5_KT_ENTRY* ptr = malloc(sizeof(RUBY_KRB5_KT_ENTRY));
  memset(ptr, 0, sizeof(RUBY_KRB5_KT_ENTRY));
  return Data_Wrap_Struct(klass, 0, rkrb5_kt_entry_free, ptr);
}

/*
 * call-seq:
 *
 *   Kerberos::Krb5::Keytab::Entry.new
 *
 * Creates and returns a new Kerberos::Krb5::Keytab::Entry object. These
 * objects are what is typically returned from the various Krb5::Keytab
 * methods.
 */
static VALUE rkrb5_kt_entry_initialize(VALUE self){
  return self;
}

/*
 * A custom inspect method for nicer output.
 */
static VALUE rkrb5_kt_entry_inspect(VALUE self){
  VALUE v_str;

  v_str = rb_str_new2("#<");
  rb_str_buf_cat2(v_str, rb_obj_classname(self));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "principal=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@principal")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "timestamp=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@timestamp")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "vno=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@vno")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "key=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@key")));
  rb_str_buf_cat2(v_str, " ");

  return v_str;
}

void Init_keytab_entry(){
  // The Kerberos::Krb5::Keytab::Entry class encapsulates a Kerberos keytab entry.
  cKrb5KtEntry = rb_define_class_under(cKrb5Keytab, "Entry", rb_cObject);

  // Allocation function
  rb_define_alloc_func(cKrb5KtEntry, rkrb5_kt_entry_allocate);

  // Constructor
  rb_define_method(cKrb5KtEntry, "initialize", rkrb5_kt_entry_initialize, 0);

  // Instance Methods
  rb_define_method(cKrb5KtEntry, "inspect", rkrb5_kt_entry_inspect, 0);

  // Accessors
  rb_define_attr(cKrb5KtEntry, "principal", 1, 1);
  rb_define_attr(cKrb5KtEntry, "timestamp", 1, 1);
  rb_define_attr(cKrb5KtEntry, "vno", 1, 1);
  rb_define_attr(cKrb5KtEntry, "key", 1, 1);
}
