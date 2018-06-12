PROJ=	libbpfjit

all:
	@ echo "targets"
	@ echo "	make rpm"
	@ echo "	make deb"

rpm: sljit_svn
	mkdir -p SOURCES && tar czpvf SOURCES/$(PROJ).tar.gz src sljit_svn
	rpmbuild -ba -v --define "_topdir ${PWD}" SPECS/$(PROJ).spec
	@ echo && printf "\x1B[32mRPM packages:\033[0m\n" && ls -1 RPMS/*

deb: sljit_svn
	cp -R src ./SOURCES
	dpkg-buildpackage -rfakeroot -us -uc -b
	@ echo && printf "\x1B[32mDEB packages:\033[0m\n" && ls -1 ../*.deb

sljit_svn:
	svn co svn://svn.code.sf.net/p/sljit/code@r313 sljit_svn

clean:
	make -C src -f bpfjit.mk clean
	rm -rf BUILD BUILDROOT RPMS SOURCES SRPMS
	rm -rf sljit_svn

.PHONY: all rpm deb clean
