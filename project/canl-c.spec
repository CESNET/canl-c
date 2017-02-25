Name:           canl-c
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        @SUMMARY@

Group:          System Environment/Libraries
License:        ASL 2.0
Vendor:         EMI
URL:            http://www.eu-emi.eu
Source:         http://scientific.zcu.cz/emi/emi.canl.c/%{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  bison
BuildRequires:  c-ares-devel
BuildRequires:  flex
BuildRequires:  krb5-devel
BuildRequires:  libtool
BuildRequires:  openssl-devel >= 1.1
BuildRequires:  perl
BuildRequires:  perl(Getopt::Long)
BuildRequires:  perl(POSIX)
BuildRequires:  pkgconfig
%if 0%{?fedora} || 0%{?rhel} >= 6
BuildRequires:  tex(latex)
%else
BuildRequires:  tetex-latex
%endif
%if 0%{?fedora} || 0%{?rhel} >= 7
BuildRequires:  tex(lastpage.sty)
BuildRequires:  tex(multirow.sty)
BuildRequires:  tex(ptmr7t.tfm)
BuildRequires:  tex(phvr8t.tfm)
BuildRequires:  tex(psyr.tfm)
BuildRequires:  tex(pzcmi8r.tfm)
BuildRequires:  tex(ucrr8a.pfb)
%endif

%description
@DESCRIPTION@


%package        devel
Summary:        Development files for EMI caNl
Group:          Development/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       krb5-devel%{?_isa}

%description    devel
This package contains development libraries and header files for EMI caNl.


%package        doc
Summary:        API documentation for EMI caNl
Group:          Documentation
%if 0%{?fedora} || 0%{?rhel} >= 6
BuildArch:      noarch
%endif

%description    doc
This package contains API documentation for EMI caNl.


%package        examples
Summary:        Example programs of EMI caNl
Group:          System Environment/Base
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    examples
This package contains client and server examples of EMI caNl.


%prep
%setup -q


%build
./configure --root=/ --prefix=%{_prefix} --libdir=%{_lib} --project=emi
CFLAGS="%{?optflags}" LDFLAGS="%{?__global_ldflags}" make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
# in -doc subpackage
rm -f %{buildroot}%{_defaultdocdir}/%{name}-%{version}/README
rm -f %{buildroot}%{_defaultdocdir}/%{name}-%{version}/canl.pdf
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la


%clean
rm -rf %{buildroot}


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%{!?_licensedir:%global license %doc}
%defattr(-,root,root)
%doc ChangeLog README
%license LICENSE
%{_libdir}/libcanl_c.so.4
%{_libdir}/libcanl_c.so.4.*

%files devel
%defattr(-,root,root)
%{_includedir}/*.h
%{_libdir}/libcanl_c.so

%files doc
%defattr(-,root,root)
%license LICENSE
%doc canl.pdf

%files examples
%defattr(-,root,root)
%{_bindir}/*


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@
- automatically generated package
