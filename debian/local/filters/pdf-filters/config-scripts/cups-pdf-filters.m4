dnl General checks

AC_HEADER_DIRENT
AC_CHECK_HEADERS([zlib.h])

dnl Needed for pdftopdf filter compilation

CXXFLAGS="-DPDFTOPDF $CXXFLAGS"

dnl poppler source dir

AC_ARG_WITH([poppler-source],[  --with-poppler-source=PATH      poppler source directory path],
  [POPPLER_SRCDIR=$withval],
  [POPPLER_SRCDIR=`eval echo $includedir`])
AC_SUBST(POPPLER_SRCDIR)

dnl Switch over to C++.
AC_LANG(C++)

dnl check poppler
AC_CHECK_LIB(poppler,main,
  [ POPPLER_LIBS=-lpoppler],
  [ echo "*** poppler library not found. ***";exit ]
)
AC_SUBST(POPPLER_LIBS)

dnl check if GlobalParams::GlobalParams has a argument
if grep "GlobalParams(char \*cfgFileName)" $POPPLER_SRCDIR/poppler/GlobalParams.h >/dev/null ;then
    AC_DEFINE([GLOBALPARAMS_HAS_A_ARG],,[GlobalParams::GlobalParams has a argument.])
fi

dnl check if Parser:Parser has two arguments
if grep "Parser(XRef \*xrefA, Lexer \*lexerA)" $POPPLER_SRCDIR/poppler/Parser.h >/dev/null ;then
    AC_DEFINE([PARSER_HAS_2_ARGS],,[Parser::Parser has two arguments.])
fi

dnl check font type enumeration
if grep "fontType1COT" $POPPLER_SRCDIR/poppler/GfxFont.h >/dev/null ;then
    AC_DEFINE([FONTTYPE_ENUM2],,[New font type enumeration])
fi

dnl check Stream::getUndecodedStream
if grep "getUndecodedStream" $POPPLER_SRCDIR/poppler/Stream.h >/dev/null ;then
    AC_DEFINE([HAVE_GETUNDECODEDSTREAM],,[Have Stream::getUndecodedStream])
fi

dnl check UGooString.h
CPPFLAGS="$CPPFLAGS -I$POPPLER_SRCDIR/poppler"
AC_CHECK_HEADER(UGooString.h,
    AC_DEFINE([HAVE_UGOOSTRING_H],,[Have UGooString.h])
,)

dnl check CharCodeToUnicode::mapToUnicode interface
CPPFLAGS="$CPPFLAGS -I$POPPLER_SRCDIR/poppler"
if grep "mapToUnicode(.*Unicode[ ][ ]*\*u" $POPPLER_SRCDIR/poppler/CharCodeToUnicode.h >/dev/null ;then
    AC_DEFINE([OLD_MAPTOUNICODE],,[Old CharCodeToUnicode::mapToUnicode])
fi

dnl Switch back to C.
AC_LANG(C)

dnl check ijs
AC_CHECK_LIB(ijs,main,
  [ IJS_LIBS=-lijs],
  [ echo "*** ijs library not found. ***";exit ]
)
AC_SUBST(IJS_LIBS)
