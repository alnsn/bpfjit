LIB=	bpfjit
SRCS=	bpfjit.c

WARNS=	4

MKPICLIB=	yes
MKSTATICLIB=	yes
LDCOMPILER=	yes
SHLIB_MAJOR=	1
SHLIB_MINOR=	0
SHLIB_TEENY=	0

COPTS+=		-O2 -g
CPPFLAGS+=	-DSLJIT_CONFIG_AUTO=1
CPPFLAGS+=	-I ../../sljit/sljit_src/
# XXX		^^^^^^^^^^^^^^^^^^^^^^^^^

#LDADD+=		-lsljit
#LDFLAGS+=	-L ../../sljit/bin
## XXX		^^^^^^^^^^^^^^^^^^

.include <mkc.lib.mk>
