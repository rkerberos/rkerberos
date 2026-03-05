
require 'mkmf'

# Prefer pkg-config for krb5 and dependencies, fallback to manual checks
if pkg_config('krb5')
  # pkg_config sets cflags/libs for krb5
else
  if File::ALT_SEPARATOR
    if ['a'].pack('P').length > 4 # 64-bit
      dir_config('rkerberos', 'C:/Progra~1/MIT/Kerberos')
    else
      dir_config('rkerberos', 'C:/Progra~2/MIT/Kerberos')
    end

    require 'mkmf'

    # Windows-specific configuration
    if RUBY_PLATFORM =~ /mswin|mingw|windows/
      kfw_dir = ENV['KRB5_DIR'] || 'C:/Program Files/MIT/Kerberos'
      kfw_inc = ENV['KRB5_INCLUDE'] || File.join(kfw_dir, 'include')
      kfw_lib = ENV['KRB5_LIB'] || File.join(kfw_dir, 'lib')
      $INCFLAGS << " -I\"#{kfw_inc}\""
      $LDFLAGS << " -L\"#{kfw_lib}\""

      # headers
      have_header('krb5.h')
      profile_header = have_header('profile.h')

      # libraries needed for base functionality
      have_library('krb5_64') || have_library('krb5_32') || have_library('krb5')
      have_library('comerr64') || have_library('comerr32') || have_library('com_err')

      # optional profile support; functions may reside in a separate library
      if profile_header
        have_library('profile64') || have_library('profile32') || have_library('profile')
        have_func('profile_init_path')
        have_func('profile_release')
      end

      # kadm5clnt and kdb5 are not always present in KfW, so don't fail if missing
      if have_library('kadm5clnt')
        $defs.push("-DHAVE_KADM5_ADMIN_H=1")
      end
      have_library('kdb5')
    else
      # Try to use pkg-config first
      def have_pkg_config_lib(lib)
        pkg = "pkg-config --exists #{lib}"
        system(pkg)
      end

      # Check for krb5
      if have_pkg_config_lib('krb5')
        $CFLAGS << " `pkg-config --cflags krb5`"
        $LDFLAGS << " `pkg-config --libs krb5`"
      end
      have_header('krb5.h')
      have_library('krb5')

      # profile API may be present separately or baked into krb5
      profile_header = have_header('profile.h')
      if profile_header
        have_library('profile')
        have_func('profile_init_path')
        have_func('profile_release')
      end

      # Check for com_err
      if have_pkg_config_lib('com_err')
        $CFLAGS << " `pkg-config --cflags com_err`"
        $LDFLAGS << " `pkg-config --libs com_err`"
      end
      have_library('com_err')

      # Check for kadm5clnt
      if have_pkg_config_lib('kadm5clnt')
        $CFLAGS << " `pkg-config --cflags kadm5clnt`"
        $LDFLAGS << " `pkg-config --libs kadm5clnt`"
      end
      if have_library('kadm5clnt')
        $defs.push("-DHAVE_KADM5_ADMIN_H=1")
      end

      # Check for kdb5
      if have_pkg_config_lib('kdb5')
        $CFLAGS << " `pkg-config --cflags kdb5`"
        $LDFLAGS << " `pkg-config --libs kdb5`"
      end
      have_library('kdb5')
    end
  end
end

create_makefile('rkerberos/rkerberos')
