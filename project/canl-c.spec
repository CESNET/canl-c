%global is_fedora %(rpm -q --quiet fedora-release && echo 1 || echo 0)

Name:           canl-c
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        @SUMMARY@

Group:          System Environment/Libraries
License:        ASL 2.0
Vendor:         EMI
Url:            @URL@
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/emi.canl.c/%{version}/src/%{name}-@VERSION@.src.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  bison
BuildRequires:  c-ares-devel%{?_isa}
BuildRequires:  chrpath
BuildRequires:  flex
BuildRequires:  krb5-devel%{?_isa}
BuildRequires:  libtool
BuildRequires:  openssl-devel%{?_isa}
BuildRequires:  pkgconfig
%if %is_fedora
BuildRequires:  texlive-latex
%else
BuildRequires:  tetex-latex
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
find $RPM_BUILD_ROOT -name '*.la' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*.a' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*' -print | xargs -I {} -i bash -c "chrpath -d {} > /dev/null 2>&1" || echo 'Stripped RPATH'


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root)
%dir /usr/share/doc/%{name}-%{version}
/usr/share/doc/%{name}-%{version}/*.pdf
/usr/%{_lib}/libcanl_c.so.@MAJOR@.@MINOR@.@REVISION@
/usr/%{_lib}/libcanl_c.so.@MAJOR@

%files devel
%defattr(-,root,root)
/usr/include/*.h
/usr/%{_lib}/libcanl_c.so

%files examples
%defattr(-,root,root)
/usr/bin/*


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package
