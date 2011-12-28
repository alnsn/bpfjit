PROG=	bpfjit_benchmark
SRCS=	benchmark.c

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../src
CPPFLAGS+=	-DSLJIT_CONFIG_AUTO=1
CPPFLAGS+=	-I ../sljit/sljit_src/

LDADD+=		-lpcap -lbpfjit -lsljit
LDFLAGS+=	-L ${.OBJDIR}/../src
LDFLAGS+=	-L ${.OBJDIR}/../sljit/sljit_src

.include <mkc.prog.mk>
