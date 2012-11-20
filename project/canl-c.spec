Name:           canl-c
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        @SUMMARY@

Group:          System Environment/Libraries
License:        ASL 2.0
Vendor:         EMI
Url:            http://www.eu-emi.eu
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/emi.canl.c/%{version}/src/%{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  bison
BuildRequires:  c-ares-devel%{?_isa}
BuildRequires:  flex
BuildRequires:  krb5-devel%{?_isa}
BuildRequires:  libtool
BuildRequires:  openssl-devel%{?_isa}
BuildRequires:  pkgconfig
%if %{?fedora}%{!?fedora:0} >= 9 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  tex(latex)
%else
BuildRequires:  tetex-latex
%endif
%if %{?fedora}%{!?fedora:0} >= 19
BuildRequires:  tex(comment.sty)
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
This package contains development libraries and header files for EMI caNL.


%package        examples
Summary:        Example programs of EMI caNl
Group:          System Environment/Base

%description    examples
This package contains client and server examples of EMI caNL.


%prep
%setup -q


%build
/usr/bin/perl ./configure --thrflavour= --nothrflavour= --root=/ --prefix=/usr --libdir=%{_lib} --project=emi --module canl.c
make


%check
make check


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
# in -devel subpackage
rm -f $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/canl.pdf
find $RPM_BUILD_ROOT -name '*.la' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*.a' -exec rm -rf {} \;


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root)
%doc LICENSE project/ChangeLog
%{_libdir}/libcanl_c.so.*

%files devel
%defattr(-,root,root)
%doc canl.pdf
%{_includedir}/*.h
%{_libdir}/libcanl_c.so

%files examples
%defattr(-,root,root)
%{_bindir}/*


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package
