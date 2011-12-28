Just-in-Time compilation for Berkeley Packet Filter.

You need sljit (http://sljit.sourceforge.net/) and mk-configure
(http://sourceforge.net/projects/mk-configure/) to build bpfjit.

It is recommended to use pkgsrc and install devel/mk-configure.
The pkgsrc guide is available here http://www.netbsd.org/docs/pkgsrc/

BUILDING
========

Extract sljit tarball to sljit/ subdirectory. Make sure you pass
--keep-old-files (-k) option to tar to keep Makefiles from bpfjit.

	$ cd sljit/
	$ tar zktf /path/to/sljit-0.86.tar.gz

Then you can build bpfjit with this command

	$ mkcmake

and install:

	$ export DESTDIR=/path/of/your/choice
	$ env PREFIX=/ mkcmake install

TESTING
=======

	$ env LD_LIRARY_PATH=${DESTDIR} ${DESTDIR}/bin/bpfjit_test
	$ echo $?

You should see zero exit status.
