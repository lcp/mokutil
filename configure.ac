#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([mokutil], [0.0.1], [glin@suse.com])
AM_INIT_AUTOMAKE([1.11 -Wno-portability tar-ustar dist-xz no-dist-gzip])
AC_CONFIG_SRCDIR([src/mokutil.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [turn on debug]), CFLAGS="$CFLAGS -g")

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

PKG_CHECK_MODULES(OPENSSL, [openssl >= 0.9.8])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
