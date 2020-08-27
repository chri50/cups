dnl
dnl Support for packaging CUPS in a Snap.
dnl
dnl Copyright © 2020 by Till Kamppeter
dnl Copyright © 2007-2019 by Apple Inc.
dnl
dnl Licensed under Apache License v2.0.  See the file "LICENSE" for more
dnl information.
dnl

# Snap packaging support

AC_ARG_ENABLE(snap, [  --enable-snap           enable support for packaging CUPS in a Snap])

APPARMORLIBS=""
SNAPDGLIBLIBS=""
ENABLE_SNAP="NO"

if test "x$PKGCONFIG" != x -a x$enable_snap != xno; then
	AC_MSG_CHECKING(for libapparmor)
	if $PKGCONFIG --exists libapparmor; then
		AC_MSG_RESULT(yes)
		CFLAGS="$CFLAGS `$PKGCONFIG --cflags libapparmor`"
		APPARMORLIBS="`$PKGCONFIG --libs libapparmor`"
		AC_DEFINE(HAVE_APPARMOR)
		AC_MSG_CHECKING(for snapd-glib)
		if $PKGCONFIG --exists snapd-glib glib-2.0 gio-2.0; then
			AC_MSG_RESULT(yes)
			CFLAGS="$CFLAGS `$PKGCONFIG --cflags snapd-glib glib-2.0 gio-2.0`"
			SNAPDGLIBLIBS="`$PKGCONFIG --libs snapd-glib glib-2.0 gio-2.0`"
			AC_DEFINE(HAVE_SNAPDGLIB)
			AC_DEFINE(BUILD_SNAP)
			ENABLE_SNAP="YES"
		else
			AC_MSG_RESULT(no)
		fi
	else
		AC_MSG_RESULT(no)
	fi
fi

AC_MSG_CHECKING(for Snap support)
if test "x$ENABLE_SNAP" != "xNO"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_SUBST(APPARMORLIBS)
AC_SUBST(SNAPDGLIBLIBS)
