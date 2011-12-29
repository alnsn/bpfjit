PROG=	bpfjit_test
SRCS=	main.c util.c test_empty.c test_ld.c test_ldx.c

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../src
CPPFLAGS+=	-DSLJIT_CONFIG_AUTO=1
CPPFLAGS+=	-I ../sljit/sljit_src/

LDADD+=		-lpcap -lbpfjit -lsljit
LDFLAGS+=	-L ${.OBJDIR}/../src
LDFLAGS+=	-L ${.OBJDIR}/../sljit/sljit_src

.include <mkc.prog.mk>
