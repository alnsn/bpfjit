PROG=	test
SRCS=	main.c util.c test_ld.c

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../src
CPPFLAGS+=	-DSLJIT_CONFIG_AUTO=1
CPPFLAGS+=	-I ../../sljit/sljit_src/
# XXX		^^^^^^^^^^^^^^^^^^^^^^^^^

LDADD+=		-lpcap -lbpfjit -lsljit
LDFLAGS+=	-L ${.OBJDIR}/../src -L ../../sljit/sljit_src

.include <mkc.prog.mk>
