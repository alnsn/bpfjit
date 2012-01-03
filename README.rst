Just-in-Time Compilation for Berkeley Packet Filter
===================================================

PREREQUISITES
-------------

You need sljit (http://sljit.sourceforge.net/) and mk-configure
(http://sourceforge.net/projects/mk-configure/) to build bpfjit.

It is recommended to use pkgsrc and install devel/mk-configure.
The pkgsrc guide is available here http://www.netbsd.org/docs/pkgsrc/

The sljit code must be at revision r143 or newer.

	$ svn co https://sljit.svn.sourceforge.net/svnroot/sljit@r143 sljit

	$ tar cf sljit-r143.tar.gz sljit

BUILDING
--------

Extract sljit tarball to sljit/ subdirectory. Make sure you pass
--keep-old-files (-k) option to tar to keep Makefiles from bpfjit.

	$ cd sljit/

	$ tar zktf /path/to/sljit-r143.tar.gz

Then you can build bpfjit with this command

	$ mkcmake

and install:

	$ export DESTDIR=/path/of/your/choice

	$ env PREFIX=/ mkcmake install

TESTING
-------

	$ export LD_LIBRARY_PATH=${DESTDIR}/lib

	$ cd ${DESTDIR}

	$ ./bin/bpfjit_test

	$ echo $?

You should see zero exit status.
