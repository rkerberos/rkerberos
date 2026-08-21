#ifdef HAVE_KADM5_ADMIN_H
#include <rkerberos.h>

VALUE cKadm5Policy;


// TypedData functions for RUBY_KADM5_POLICY
static void rkadm5_policy_typed_free(void *ptr) {
  if (!ptr) return;
  RUBY_KADM5_POLICY *p = (RUBY_KADM5_POLICY *)ptr;
  if (p->ctx)
    krb5_free_context(p->ctx);
  free(p);
}

static size_t rkadm5_policy_typed_size(const void *ptr) {
  return sizeof(RUBY_KADM5_POLICY);
}

const rb_data_type_t rkadm5_policy_data_type = {
  "RUBY_KADM5_POLICY",
  {NULL, rkadm5_policy_typed_free, rkadm5_policy_typed_size,},
  NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY
};

// Allocation function for the Kerberos::Kadm5::Policy class.
static VALUE rkadm5_policy_allocate(VALUE klass){
  RUBY_KADM5_POLICY* ptr = ALLOC(RUBY_KADM5_POLICY);
  memset(ptr, 0, sizeof(RUBY_KADM5_POLICY));
  return TypedData_Wrap_Struct(klass, &rkadm5_policy_data_type, ptr);
}

/*
 * call-seq:
 *   Kerberos::Kadm5::Policy.new(name:, min_life: nil, max_life: nil,
 *     min_length: nil, min_classes: nil, history_num: nil)
 *
 * Returns a new policy object using the keyword arguments you choose to pass.
 * This does NOT actually create the policy within Kerberos. To do that pass
 * your Policy object to the Kadm5.create_policy method.
 *
 * The possible options are:
 *
 * * name        - the name of the policy (mandatory)
 * * min_life    - minimum lifetime of a password
 * * max_life    - maximum lifetime of a password
 * * min_length  - minimum length of a password
 * * min_classes - minimum number of character classes allowed in a password
 * * history_num - number of past key kept for a principal
 *
 * If you do not provide a :name then an ArgumentError will be raised.
 */
static VALUE rkadm5_policy_init(int argc, VALUE* argv, VALUE self){
  RUBY_KADM5_POLICY* ptr;
  VALUE v_options;
  VALUE v_name, v_minlife, v_maxlife, v_minlength;
  VALUE v_minclasses, v_historynum;
  ID kw_table[6] = {
    rb_intern("name"), rb_intern("min_life"), rb_intern("max_life"),
    rb_intern("min_length"), rb_intern("min_classes"), rb_intern("history_num")
  };
  VALUE kw_vals[6];

  TypedData_Get_Struct(self, RUBY_KADM5_POLICY, &rkadm5_policy_data_type, ptr);

  rb_scan_args(argc, argv, "0:", &v_options);

  if(NIL_P(v_options))
    v_options = rb_hash_new();

  rb_get_kwargs(v_options, kw_table, 1, 5, kw_vals);
  v_name = kw_vals[0];
  v_minlife = kw_vals[1] == Qundef ? Qnil : kw_vals[1];
  v_maxlife = kw_vals[2] == Qundef ? Qnil : kw_vals[2];
  v_minlength = kw_vals[3] == Qundef ? Qnil : kw_vals[3];
  v_minclasses = kw_vals[4] == Qundef ? Qnil : kw_vals[4];
  v_historynum = kw_vals[5] == Qundef ? Qnil : kw_vals[5];

  ptr->policy.policy = StringValueCStr(v_name);
  rb_iv_set(self, "@policy", v_name);

  if(!NIL_P(v_minlife)){
    ptr->policy.pw_min_life = NUM2LONG(v_minlife);
    rb_iv_set(self, "@min_life", v_minlife);
  }
  else{
    rb_iv_set(self, "@min_life", Qnil);
  }

  if(!NIL_P(v_maxlife)){
    ptr->policy.pw_max_life = NUM2LONG(v_maxlife);
    rb_iv_set(self, "@max_life", v_maxlife);
  }
  else{
    rb_iv_set(self, "@max_life", Qnil);
  }

  if(!NIL_P(v_minlength)){
    ptr->policy.pw_min_length = NUM2LONG(v_minlength);
    rb_iv_set(self, "@min_length", v_minlength);
  }
  else{
    rb_iv_set(self, "@min_length", Qnil);
  }

  if(!NIL_P(v_minclasses)){
    ptr->policy.pw_min_classes = NUM2LONG(v_minclasses);
    rb_iv_set(self, "@min_classes", v_minclasses);
  }
  else{
    rb_iv_set(self, "@min_classes", Qnil);
  }

  if(!NIL_P(v_historynum)){
    ptr->policy.pw_history_num = NUM2LONG(v_historynum);
    rb_iv_set(self, "@history_num", v_historynum);
  }
  else{
    rb_iv_set(self, "@history_num", Qnil);
  }

  return self;
}

/*
 * call-seq:
 *   policy.inspect
 *
 * A custom inspect method for Policy objects.
 */
static VALUE rkadm5_policy_inspect(VALUE self){
  VALUE v_str;

  v_str = rb_str_new2("#<");
  rb_str_buf_cat2(v_str, rb_obj_classname(self));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "policy=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@policy")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "min_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@min_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "max_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@max_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "min_length=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@min_length")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "min_classes=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@min_classes")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "history_num=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@history_num")));

  rb_str_buf_cat2(v_str, ">");

  return v_str;
}

void Init_policy(void){
  /* The Kerberos::Kadm5::Policy class encapsulates a Kerberos policy. */
  cKadm5Policy = rb_define_class_under(cKadm5, "Policy", rb_cObject);

  // Allocation Function

  rb_define_alloc_func(cKadm5Policy, rkadm5_policy_allocate);

  // Initialization Function

  rb_define_method(cKadm5Policy, "initialize", rkadm5_policy_init, -1);

  // Instance methods

  rb_define_method(cKadm5Policy, "inspect", rkadm5_policy_inspect, 0);

  // Accessors

  /* The name of the policy. */
  rb_define_attr(cKadm5Policy, "policy", 1, 0);

  /* The minimum password lifetime, in seconds. */
  rb_define_attr(cKadm5Policy, "min_life", 1, 1);

  /* The maximum duration of a password, in seconds. */
  rb_define_attr(cKadm5Policy, "max_life", 1, 1);

  /* The minimum password length. */
  rb_define_attr(cKadm5Policy, "min_length", 1, 1);

  /* The minimum number of character classes (1-5). */
  rb_define_attr(cKadm5Policy, "min_classes", 1, 1);

  /* The number of past passwords that are stored. */
  rb_define_attr(cKadm5Policy, "history_num", 1, 1);

  // Aliases

  rb_define_alias(cKadm5Policy, "name", "policy");
}
#endif
