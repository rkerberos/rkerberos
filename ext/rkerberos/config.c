#include <rkerberos.h>

VALUE cKadm5Config;

static void rkadm5_config_free(RUBY_KADM5_CONFIG* ptr){
  if(!ptr)
    return;

  kadm5_free_config_params(ptr->ctx, &ptr->config);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

const rb_data_type_t kadm5_config_type = {
  .wrap_struct_name = "kadm5_config",
  .function = {
    .dfree = (void (*)(void*))rkadm5_config_free,
    .dsize = NULL,
    .dmark = NULL,
  },
  .data = NULL,
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Krb5 class.
static VALUE rkadm5_config_allocate(VALUE klass){
  RUBY_KADM5_CONFIG* ptr = malloc(sizeof(RUBY_KADM5_CONFIG));
  memset(ptr, 0, sizeof(RUBY_KADM5_CONFIG));
  return TypedData_Wrap_Struct(klass, &kadm5_config_type, ptr);
}

/*
 * Returns a Kerberos::Kadm5::Config object. This object contains Kerberos
 * admin configuration.
 *
 * Note that the returned object is frozen. Changes made to the Kerberos
 * admin configuration options after the call will not be reflected in this
 * object.
 */
static VALUE rkadm5_config_initialize(VALUE self){
  RUBY_KADM5_CONFIG* ptr;
  krb5_error_code kerror;

  TypedData_Get_Struct(self, RUBY_KADM5_CONFIG, &kadm5_config_type, ptr);

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  kerror = kadm5_get_config_params(
    ptr->ctx,
    1,
    &ptr->config,
    &ptr->config
  );

  if(kerror)
    rb_raise(cKrb5Exception, "kadm5_get_config_params: %s", error_message(kerror));

  if(ptr->config.realm)
    rb_iv_set(self, "@realm", rb_str_new2(ptr->config.realm));
  else
    rb_iv_set(self, "@realm", Qnil);

  if(ptr->config.admin_server)
    rb_iv_set(self, "@admin_server", rb_str_new2(ptr->config.admin_server));
  else
    rb_iv_set(self, "@admin_server", Qnil);

  if(ptr->config.kadmind_port)
    rb_iv_set(self, "@kadmind_port", INT2FIX(ptr->config.kadmind_port));
  else
    rb_iv_set(self, "@kadmind_port", Qnil);

  if(ptr->config.kpasswd_port)
    rb_iv_set(self, "@kpasswd_port", INT2FIX(ptr->config.kpasswd_port));
  else
    rb_iv_set(self, "@kpasswd_port", Qnil);

  if(ptr->config.acl_file)
    rb_iv_set(self, "@acl_file", rb_str_new2(ptr->config.acl_file));
  else
    rb_iv_set(self, "@acl_file", Qnil);

  if(ptr->config.dict_file)
    rb_iv_set(self, "@dict_file", rb_str_new2(ptr->config.dict_file));
  else
    rb_iv_set(self, "@dict_file", Qnil);

  if(ptr->config.stash_file)
    rb_iv_set(self, "@stash_file", rb_str_new2(ptr->config.stash_file));
  else
    rb_iv_set(self, "@stash_file", Qnil);

  if(ptr->config.mkey_name)
    rb_iv_set(self, "@mkey_name", rb_str_new2(ptr->config.mkey_name));
  else
    rb_iv_set(self, "@mkey_name", Qnil);

  if(ptr->config.mkey_from_kbd)
    rb_iv_set(self, "@mkey_from_kbd", INT2FIX(ptr->config.mkey_from_kbd));
  else
    rb_iv_set(self, "@mkey_from_kbd", Qnil);

  if(ptr->config.enctype)
    rb_iv_set(self, "@enctype", INT2FIX(ptr->config.enctype));
  else
    rb_iv_set(self, "@enctype", Qnil);

  if(ptr->config.max_life)
    rb_iv_set(self, "@max_life", INT2FIX(ptr->config.max_life));
  else
    rb_iv_set(self, "@max_life", Qnil);

  if(ptr->config.max_rlife)
    rb_iv_set(self, "@max_rlife", INT2FIX(ptr->config.max_rlife));
  else
    rb_iv_set(self, "@max_rlife", Qnil);

  if(ptr->config.expiration)
    rb_iv_set(self, "@expiration", rb_time_new(ptr->config.expiration, 0));
  else
    rb_iv_set(self, "@expiration", Qnil);

  if(ptr->config.flags)
    rb_iv_set(self, "@flags", INT2FIX(ptr->config.flags));
  else
    rb_iv_set(self, "@flags", Qnil);

  if(ptr->config.kvno)
    rb_iv_set(self, "@kvno", INT2FIX(ptr->config.kvno));
  else
    rb_iv_set(self, "@kvno", Qnil);

  if(ptr->config.iprop_enabled)
    rb_iv_set(self, "@iprop_enabled", Qtrue);
  else
    rb_iv_set(self, "@iprop_enabled", Qfalse);

  if(ptr->config.iprop_logfile)
    rb_iv_set(self, "@iprop_logfile", rb_str_new2(ptr->config.iprop_logfile));
  else
    rb_iv_set(self, "@iprop_logfile", Qnil);

  if(ptr->config.iprop_poll_time)
    rb_iv_set(self, "@iprop_poll_time", INT2FIX(ptr->config.iprop_poll_time));
  else
    rb_iv_set(self, "@iprop_poll_time", Qnil);

  if(ptr->config.iprop_port)
    rb_iv_set(self, "@iprop_port", INT2FIX(ptr->config.iprop_port));
  else
    rb_iv_set(self, "@iprop_port", Qnil);

  if(ptr->config.num_keysalts)
    rb_iv_set(self, "@num_keysalts", INT2FIX(ptr->config.num_keysalts));
  else
    rb_iv_set(self, "@num_keysalts", Qnil);

  // Not very useful at the moment. How do you iterate over an enum in C?
  if(ptr->config.keysalts)
    rb_iv_set(self, "@keysalts", INT2FIX(ptr->config.keysalts));
  else
    rb_iv_set(self, "@keysalts", Qnil);

  // This is read only data
  rb_obj_freeze(self);

  return self;
}

static VALUE rkadm5_config_inspect(VALUE self){
  VALUE v_str;

  v_str = rb_str_new2("#<");
  rb_str_buf_cat2(v_str, rb_obj_classname(self));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "acl_file=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@acl_file")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "admin_server=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@admin_server")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "dict_file=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@dict_file")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "enctype=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@enctype")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "expiration=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@expiration")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "flags=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@flags")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "iprop_enabled=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@iprop_enabled")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "iprop_logfile=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@iprop_logfile")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "iprop_poll_time=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@iprop_poll_time")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "iprop_port=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@iprop_port")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "kadmind_port=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@kadmind_port")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "keysalts=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@keysalts")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "kpasswd_port=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@kpasswd_port")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "kvno=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@kvno")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mkey_name=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mkey_name")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mkey_from_kbd=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mkey_from_kbd")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "maxlife=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@maxlife")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "maxrlife=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@maxrlife")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "num_keysalts=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@num_keysalts")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "realm=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@realm")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "stash_file=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@stash_file")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, ">");

  return v_str;
}

void Init_config(){
  cKadm5Config = rb_define_class_under(cKadm5, "Config", rb_cObject);

  // Allocation function

  rb_define_alloc_func(cKadm5Config, rkadm5_config_allocate);

  // Initializer

  rb_define_method(cKadm5Config, "initialize", rkadm5_config_initialize, 0);

  // Methods

  rb_define_method(cKadm5Config, "inspect", rkadm5_config_inspect, 0);

  // Accessors

  rb_define_attr(cKadm5Config, "acl_file", 1, 0);
  rb_define_attr(cKadm5Config, "admin_server", 1, 0);
  rb_define_attr(cKadm5Config, "dict_file", 1, 0);
  rb_define_attr(cKadm5Config, "enctype", 1, 0);
  rb_define_attr(cKadm5Config, "expiration", 1, 0);
  rb_define_attr(cKadm5Config, "flags", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_enabled", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_logfile", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_poll_time", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_port", 1, 0);
  rb_define_attr(cKadm5Config, "kadmind_port", 1, 0);
  rb_define_attr(cKadm5Config, "keysalts", 1, 0);
  rb_define_attr(cKadm5Config, "kpasswd_port", 1, 0);
  rb_define_attr(cKadm5Config, "kvno", 1, 0);
  rb_define_attr(cKadm5Config, "mkey_name", 1, 0);
  rb_define_attr(cKadm5Config, "mkey_from_kbd", 1, 0);
  rb_define_attr(cKadm5Config, "max_life", 1, 0);
  rb_define_attr(cKadm5Config, "max_rlife", 1, 0);
  rb_define_attr(cKadm5Config, "num_keysalts", 1, 0);
  rb_define_attr(cKadm5Config, "realm", 1, 0);
  rb_define_attr(cKadm5Config, "stash_file", 1, 0);
}
