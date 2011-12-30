PROG=	bpfjit_test
SRCS=	main.c util.c test_empty.c test_ld.c test_ldx.c test_alu.c

WARNS=	4

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../src

LDADD+=		-lpcap -lbpfjit -lsljit
LDFLAGS+=	-L ${.OBJDIR}/../src
LDFLAGS+=	-L ${.OBJDIR}/../sljit/sljit_src

.include <mkc.prog.mk>
