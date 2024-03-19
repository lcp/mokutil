#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([mokutil], [0.7.2], [glin@suse.com])
AM_INIT_AUTOMAKE([1.11 -Wno-portability tar-ustar dist-bzip2 no-dist-gzip])
AC_CONFIG_SRCDIR([src/mokutil.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

# Checks for libraries.
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [turn on debug]), CFLAGS="$CFLAGS -g")

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h crypt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

#### gcc warning flags
dnl ---------------------------------------------------------------------------
dnl - Use strict options (default enabled for devs, disabled in releases)
dnl ---------------------------------------------------------------------------
dnl if .git directory is present, considering we are working in the repository
if test -d ".git"; then
	default_strict=yes
else
	default_strict=no
fi

WARNINGFLAGS_C="$WARNINGFLAGS_C -std=gnu11 -fshort-wchar"

AC_ARG_ENABLE(strict, AS_HELP_STRING([--enable-strict],[Enable strict compilation options]), enable_strict=$enableval,
		enable_strict=$default_strict)
if test x$enable_strict != xno; then
	if test "$GCC" = "yes"; then
		WARNINGFLAGS_C="$WARNINGFLAGS_C -Werror"
	fi
fi

if test "$GCC" = "yes"; then
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wall -Wextra"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wcast-align -Wno-uninitialized"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wmissing-declarations"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wredundant-decls"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wpointer-arith"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wcast-align"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wwrite-strings"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Winit-self"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wreturn-type"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Werror=format-nonliteral"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Werror=format-security"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wmissing-include-dirs"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wmissing-format-attribute"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wclobbered"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wempty-body"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wignored-qualifiers"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Werror=sign-compare"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wtype-limits"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wuninitialized"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wunused"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Waggregate-return"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wdeclaration-after-statement"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wshadow"
	WARNINGFLAGS_C="$WARNINGFLAGS_C -Werror=strict-aliasing"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Winline"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Wmissing-parameter-type"
#	WARNINGFLAGS_C="$WARNINGFLAGS_C -Woverride-init"
else
	WARNINGFLAGS_C="$WARNINGFLAGS_C"
fi
AC_SUBST(WARNINGFLAGS_C)

# Checks for library functions.
AC_CHECK_FUNCS([memset])

PKG_CHECK_MODULES(OPENSSL, [openssl >= 0.9.8])
PKG_CHECK_MODULES(EFIVAR, [efivar >= 0.12])
PKG_CHECK_MODULES(LIBKEYUTILS, [libkeyutils >= 1.5])

AC_ARG_WITH([bash-completion-dir],
    AS_HELP_STRING([--with-bash-completion-dir[=PATH]],
        [Install the bash auto-completion script in this directory. @<:@default=yes@:>@]),
    [],
    [with_bash_completion_dir=yes])

if test "x$with_bash_completion_dir" = "xyes"; then
    PKG_CHECK_MODULES([BASH_COMPLETION], [bash-completion >= 2.0],
        [BASH_COMPLETION_DIR="`$PKG_CONFIG --variable=completionsdir bash-completion`"],
        [BASH_COMPLETION_DIR="$datadir/bash-completion/completions"])
else
    BASH_COMPLETION_DIR="$with_bash_completion_dir"
fi

AC_SUBST([BASH_COMPLETION_DIR])
AM_CONDITIONAL([ENABLE_BASH_COMPLETION],[test "x$with_bash_completion_dir" != "xno"])

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 man/Makefile])
AC_OUTPUT
