Just-in-Time Compilation for Berkeley Packet Filter
===================================================

[![Build Status](https://travis-ci.org/alnsn/bpfjit.svg?branch=master)](https://travis-ci.org/alnsn/bpfjit)

Prerequisites
-------------

You need sljit (http://sljit.sourceforge.net/) and mk-configure
(http://sourceforge.net/projects/mk-configure/) to build bpfjit.

It is recommended to use pkgsrc and install devel/mk-configure.
The pkgsrc guide is available at http://www.netbsd.org/docs/pkgsrc/.

The sljit code must be at revision r313 or newer:

	$ svn co https://svn.code.sf.net/p/sljit/code@r313 sljit

	$ tar cf sljit-r313.tar sljit/

Building
--------

Extract sljit tarball to sljit/ subdirectory. Make sure you pass
--keep-old-files (-k) option to tar to keep Makefiles from bpfjit.

	$ cd sljit/

	$ tar kxf /path/to/sljit-r313.tar

Then you can build bpfjit with this command

	$ mkcmake

and install:

	$ export DESTDIR=/path/of/your/choice

	$ env PREFIX=/ mkcmake install

Testing
-------

	$ export LD_LIBRARY_PATH=${DESTDIR}/lib

	$ cd ${DESTDIR}

	$ ./bin/bpfjit_test

	$ echo $?

You should see zero exit status.

Packages
--------

Just build the package, install it and link the library using the
`-lbpfjit` flag.
* RPM (tested on RHEL/CentOS 7): `make rpm`
* DEB (tested on Debian 9): `make deb`
