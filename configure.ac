# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.69)

# This project.
AC_INIT(tinysshd-convertkey, 0.2, [], [], [m4_esyscmd_s([git ls-remote --get-url])])
AC_DEFINE([GITCOMMIT], ["m4_esyscmd_s([git rev-parse --short HEAD])"])
AC_CONFIG_SRCDIR(tinysshd-convertkey.c)
AC_CONFIG_AUX_DIR(autotools)
AC_CONFIG_FILES(Makefile)
AM_INIT_AUTOMAKE(foreign no-dist no-exeext subdir-objects)

# Check for C compiler.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([ctype.h errno.h fcntl.h poll.h stdio.h stdlib.h string.h strings.h sys/stat.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memchr strcasecmp strchr strcspn])

AC_OUTPUT
