PROG=	bpfjit_benchmark
SRCS=	benchmark.c

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../src

LDADD+=		-lpcap -lbpfjit -lsljit
LDFLAGS+=	-L ${.OBJDIR}/../src
LDFLAGS+=	-L ${.OBJDIR}/../sljit/sljit_src

.include <mkc.prog.mk>
