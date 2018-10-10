AC_PREREQ([2.69])
AC_INIT(libsonic, 0.1, ernest@unstable.build)

root_dir=$(pwd)
build_libs=""
system_libs=""
libs_ldflags="-L$root_dir/deps/lib"
libs_cflags="-I$root_dir/deps/include"
link_build_deps="-lslab"
include_libh2o=yes
include_libwslay=yes
include_libuv=yes
include_libopenssl=yes

AC_DEFUN([SET_DEFLAG],[test -z "$$1" && $1="$2";])
AC_DEFUN([CHECK_BUILD],[
	if test "$include_$2" == yes
	then
		if test "$build_$2" == yes
		then
			build_libs="$build_libs $root_dir/deps/lib/$2$3.a"
			libs_ldflags="$libs_ldflags $4"
		else
			libs_ldflags="$(pkg-config $1 --libs-only-L) $(pkg-config $1 --libs-only-other) $libs_ldflags"
		fi
	fi
])
AC_DEFUN([CHECK_LINK],[
	if test "$include_$2" == yes
	then
		if test "$build_$2" == yes
		then
			link_build_deps="$link_build_deps $3"
		else
			link_build_deps="$link_build_deps $(pkg-config $1 --libs-only-l)"
		fi
	fi
])
AC_DEFUN([CHECK_LIB],[
	if test "$build_$1" == no
	then
		if test "$include_$1" == yes
		then
			$2
		fi
	else
		$3
	fi
])
AC_DEFUN([SET_DEFLAG_DEFINE],[test -z "$$1" && $1="$2"; AC_DEFINE($1, $2) AC_SUBST($1, $2)])

AC_ARG_ENABLE(lto, [AS_HELP_STRING([--enable-lto], [enable link time optimizations (-flto). If custom CFLAGS are passed, this option has no effect.])], [enable_lto=yes], [enable_lto=no])
AC_ARG_ENABLE(develop, [AS_HELP_STRING([--enable-develop], [enable development build. This sets clang as the compiler and sets a bunch of testing and debugging compiler flags.])], [enable_develop=yes], [enable_develop=no])
AC_ARG_ENABLE(build-all, [AS_HELP_STRING([--enable-build-all], [build all local dependencies])], [build_all=yes], [build_all=no])

AC_ARG_ENABLE(build-libuv, [AS_HELP_STRING([--enable-build-libuv], [build local libuv])], [build_libuv=yes], [build_libuv=no])
AC_ARG_ENABLE(build-h2o, [AS_HELP_STRING([--enable-build-h2o], [build local h2o])], [build_libh2o=yes], [build_libh2o=no])
AC_ARG_ENABLE(build-wslay, [AS_HELP_STRING([--enable-build-wslay], [build local wslay])], [build_libwslay=yes], [build_libwslay=no])
AC_ARG_ENABLE(build-openssl, [AS_HELP_STRING([--enable-build-openssl], [build local openssl])], [build_libopenssl=yes], [build_libopenssl=no])

AC_CHECK_PROG(PKGCFG,pkg-config,yes)
if test x"$PKGCFG" != x"yes" ; then
    AC_MSG_ERROR([Please install pkg-config before building libsonic.])
fi

AC_CHECK_PROG(TRUNCPROG,truncate,yes)
if test x"$TRUNCPROG" != x"yes" ; then
    AC_MSG_ERROR([Please install GNU coreutils (or just truncate) truncate before building libsonic.])
fi

AC_CHECK_PROG(XXDPROG,xxd,yes)
if test x"$XXDPROG" != x"yes" ; then
    AC_MSG_ERROR([Please install xxd before building libsonic.])
fi

AC_CHECK_PROG(TRPROG,tr,yes)
if test x"$TRPROG" != x"yes" ; then
    AC_MSG_ERROR([Please install GNU coreutils (or just tr) before building libsonic.])
fi

AC_CHECK_PROG(GITPRG,git,yes)
if test x"$GITPRG" != x"yes" ; then
    AC_MSG_ERROR([Please install git before building libsonic.])
fi

AC_CHECK_PROG(PATCHPGR,patch,yes)
if test x"$PATCHPGR" != x"yes" ; then
    AC_MSG_ERROR([Please install patch before building libsonic.])
fi

version=`git describe --tags --long 2>/dev/null || echo "untagged-$(git rev-parse --short HEAD)"`

SET_DEFLAG(TARGET_SYS, [$(uname -s)])


if test "$build_all" == yes
then
	build_libuv=yes
	build_libh2o=yes
	build_libwslay=yes
	build_libopenssl=yes
fi

# openssl builds two separate .a files
if test "$build_libopenssl" == yes
then
	build_libs="$root_dir/deps/lib/libssl.a $root_dir/deps/lib/libcrypto.a $build_libs"
fi
CHECK_BUILD(libuv, libuv)
CHECK_BUILD(libwslay, libwslay)
CHECK_BUILD(libh2o, libh2o)

CHECK_LINK(openssl, libopenssl, -lssl -lcrypto)
CHECK_LINK(libuv, libuv, -luv -lrt -lpthread -ldl)
CHECK_LINK(libwslay, libwslay, -lwslay)
CHECK_LINK(libh2o, libh2o, -lh2o)

lto=
if test "$enable_lto" == yes
then
	lto=-flto
fi

if test "$enable_develop" == yes
then
	SET_DEFLAG(CC, [clang])
	SET_DEFLAG(CXX, [clang++])
	SET_DEFLAG(EXTRA_CFLAGS,[-fsanitize=undefined -Wall])
	SET_DEFLAG(CFLAGS,[$libs_cflags -fsanitize-coverage=trace-cmp,trace-pc-guard -fprofile-instr-generate -fcoverage-mapping -ggdb])
	SET_DEFLAG_DEFINE(FUZZFLAGS,[-max_total_time=60]) # fuzzer flags
	AC_DEFINE(SONIC_DEBUG)
	AC_CHECK_PROG(SED_CHECK,sed,yes)
	if test x"$SED_CHECK" != x"yes" ; then
		AC_MSG_ERROR([Please make sure that GNU sed is installed before building libsonic.])
	fi

else
	AC_DEFINE(SONIC_INLINE)
	SET_DEFLAG(CFLAGS,[$libs_cflags -O3 $lto])
fi

SET_DEFLAG(LDFLAGS,[$libs_ldflags])

SET_DEFLAG(LIBS,["$system_libs"])
SET_DEFLAG(BUILD_LIBS,["$build_libs"])
SET_DEFLAG(LIBTOOLIZE,["libtoolize"])

AC_LANG(C)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_PROG(OBJDUMP_CHECK,nm,yes)
if test x"$OBJDUMP_CHECK" != x"yes" ; then
    AC_MSG_ERROR([Please make sure that GNU nm is installed before building libsonic.])
fi

AC_CHECK_PROG(TAIL_CHECK,tail,yes)
if test x"$TAIL_CHECK" != x"yes" ; then
    AC_MSG_ERROR([Please make sure that GNU tail is installed before building libsonic.])
fi

CHECK_LIB(libuv, [
		AC_CHECK_LIB(uv, uv_loop_close, [], [AC_MSG_ERROR([libuv not installed])])
	],[
		AC_CHECK_PROG(AUTOCONFPROG,autoconf,yes)
		if test x"$AUTOCONFPROG" != x"yes" ; then
			AC_MSG_ERROR([Please install autoconf before building libuv.])
		fi

		AC_CHECK_PROG(AUTOMAKEPROG,automake,yes)
		if test x"$AUTOMAKEPROG" != x"yes" ; then
			AC_MSG_ERROR([Please install automake before building libuv.])
		fi

		AC_CHECK_PROG(LIBTOOLIZEPROG,$LIBTOOLIZE,yes)
		if test x"$LIBTOOLIZEPROG" != x"yes" ; then
			AC_MSG_ERROR([Please install $LIBTOOLIZE before building libuv.])
		fi
])
CHECK_LIB(libh2o, [AC_CHECK_LIB(h2o, h2o_context_init, [], [AC_MSG_ERROR([h2o not installed])])], [
	AC_CHECK_PROG(CMAKEPROG,cmake,yes)
	if test x"$CMAKEPROG" != x"yes" ; then
		AC_MSG_ERROR([Please install cmake before building libh2o.])
	fi
])

CHECK_LIB(libwslay, [AC_CHECK_LIB(wslay, wslay_frame_recv, [], [AC_MSG_ERROR([wslay not installed])])], [
	AC_CHECK_PROG(AUTORECONFPROG,autoreconf,yes)
	if test x"$AUTORECONFPROG" != x"yes" ; then
		AC_MSG_ERROR([Please install autoreconf before building libwslay.])
	fi

	AC_CHECK_PROG(AUTOMAKEPROG,automake,yes)
	if test x"$AUTOMAKEPROG" != x"yes" ; then
		AC_MSG_ERROR([Please install automake before building libwslay.])
	fi

	AC_CHECK_PROG(AUTOCONF,autoconf,yes)
	if test x"$AUTOCONF" != x"yes" ; then
		AC_MSG_ERROR([Please install autoconf before building libwslay.])
	fi
])
CHECK_LIB(libopenssl, [
	AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])])
	AC_CHECK_HEADERS([openssl/opensslconf.h], [], AC_MSG_ERROR([openssl headers not found. Please make sure OpenSSL is installed and available in a standard location or pass your own CFLAGS to this script. For example: CFLAGS='$CFLAGS -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib']))
	FOUND_SSL_LIB="no"
	AC_CHECK_LIB(ssl, OPENSSL_init_ssl, [FOUND_SSL_LIB="yes"])
	AC_CHECK_LIB(ssl, SSL_library_init, [FOUND_SSL_LIB="yes"])
	AS_IF([test "x$FOUND_SSL_LIB" = xno], [AC_MSG_ERROR([library 'ssl' is required for OpenSSL])])
], [echo "nothing to check for openssl"])

AC_CHECK_HEADERS([assert.h dlfcn.h errno.h fcntl.h getopt.h libgen.h stdbool.h stdint.h stdlib.h stdio.h string.h sys/stat.h time.h unistd.h utime.h], [], AC_MSG_ERROR([system header not found]))
AC_CHECK_LIB(pthread, pthread_create, [], [AC_MSG_ERROR([pthread not available])])

AC_SUBST([BUILD_LIBUV], ["$build_libuv"])
AC_SUBST([BUILD_H2O], ["$build_libh2o"])
AC_SUBST([BUILD_WSLAY], ["$build_libwslay"])
AC_SUBST([BUILD_OPENSSL], ["$build_libopenssl"])
AC_SUBST([DEVELOP_BUILD], ["$enable_develop"])
AC_SUBST([LIBS], ["$LIBS"])
AC_SUBST([EXTRA_LIBS], ["$link_build_deps"])
AC_SUBST([BUILD_LIBS], ["$BUILD_LIBS"])
AC_SUBST([EXTRA_CFLAGS], ["$EXTRA_CFLAGS"])
AC_SUBST([CFLAGS], ["$CFLAGS"])
AC_SUBST([EXTRA_LDFLAGS], ["$EXTRA_LDFLAGS"])
AC_SUBST([LDFLAGS], ["$LDFLAGS"])
AC_SUBST([ROOT_DIR], ["$root_dir"])
AC_SUBST(bindir, ["$bindir"])
AC_SUBST(TARGET_SYS, ["$TARGET_SYS"])

AC_MSG_NOTICE([using enable_develop=$enable_develop])
AC_MSG_NOTICE([using enable_lto=$enable_lto])
AC_MSG_NOTICE([using ROOT_DIR=$root_dir])
AC_MSG_NOTICE([using CC=$CC])
AC_MSG_NOTICE([using CXX=$CXX])
AC_MSG_NOTICE([using CFLAGS=$CFLAGS])
AC_MSG_NOTICE([using LDFLAGS=$LDFLAGS])
AC_MSG_NOTICE([using build_libuv=$build_libuv])
AC_MSG_NOTICE([using build_libh2o=$build_libh2o])
AC_MSG_NOTICE([using build_libwslay=$build_libwslay])
AC_MSG_NOTICE([using build_libopenssl=$build_libopenssl])
AC_MSG_NOTICE([using include_libuv=$include_libuv])
AC_MSG_NOTICE([using include_libh2o=$include_libh2o])
AC_MSG_NOTICE([using include_libwslay=$include_libwslay])
AC_MSG_NOTICE([using include_libopenssl=$include_libopenssl])
AC_MSG_NOTICE([using BUILD_LIBS=$BUILD_LIBS])
AC_MSG_NOTICE([using LIBS=$LIBS])
AC_MSG_NOTICE([using EXTRA_LIBS=$EXTRA_LIBS])

AC_DEFINE_UNQUOTED(SONIC_VERSION, ["$version"])
AC_SUBST(SONIC_VERSION, ["$version"])

AC_CONFIG_FILES([Makefile
				 src/Makefile
				 test/helper.sh
				 deps/Makefile
                 test/Makefile])

AC_CONFIG_HEADERS(src/config.h)

AC_OUTPUT
