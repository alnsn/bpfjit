%define version	%(cat %{_topdir}/version.txt)

Name:		libbpfjit
Version:	%{version}
Release:	1%{?dist}
Summary:	bpfjit library - JIT compiler for the BPF byte-code
Group:		System Environment/Libraries
License:	BSD
URL:		https://github.com/alnsn/bpfjit
Source0:	libbpfjit.tar.gz

BuildRequires:	make
BuildRequires:	libtool
BuildRequires:	libpcap-devel

%description
bpfjit: Just-in-Time Compilation for Berkeley Packet Filter.

%prep
%setup -q -n src

%build
make -f bpfjit.mk %{?_smp_mflags} LIBDIR=%{_libdir}

%install
make -f bpfjit.mk install \
    DESTDIR=%{buildroot} LIBDIR=%{_libdir} INCDIR=%{_includedir}

%files
%{_libdir}/*
%{_includedir}/*
#%{_mandir}/*

%changelog
