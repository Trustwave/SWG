%define pkgname         frox
%define rpmbuild        %(pwd)
%define _specdir        %{rpmbuild}/
%define _builddir       %{rpmbuild}/%{pkgname}
%define _sourcedir      %{rpmbuild}/pkg
%define _srcrpmdir      %{rpmbuild}/
%define _svnr           %(svn info | grep 'Last Changed Rev: '|sed s"/Last Changed Rev: /r/")

Name:	    %{pkgname}
Version:	0.7.23
Release:	1%{?dist}
Summary:	FTP Proxy. %{_svnr}
Group:	    System Environment/Daemons	
License:	GPLv2

Source1:    frox.conf
Source2:    frox.logrotate
Source3:    frox_configure.pl
Source4:    frox_start.sh
Source5:    frox_stop.sh 

BuildRequires:	devenv-wasp
BuildRequires:	autoconf
BuildRequires:	automake

%description
Frox proxy package.

%debug_package

%build
WASP_ROOT="$(dirname %{rpmbuild})/WASP"
#WASP_ROOT=/sandbox/src/WASP
CONF_OPTS="--enable-local-cache --enable-virus-scan --enable-ssl --enable-transparent-data --enable-ccp --enable-configfile=/etc/frox.conf --prefix=/tmp --enable-run-as-root --enable-libiptc"
    
CPPFLAGS="-D__EXPORTED_HEADERS__ -I${WASP_ROOT}/Proxy2/FTP_EXT_Plugin/"
CFLAGS=" -ggdb -O2 -Wall -Werror -Wno-error=strict-aliasing -Wno-error=implicit-function-declaration"
LDFLAGS="-L${WASP_ROOT}/lib"

./configure $CONF_OPTS CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" CFLAGS="$CFLAGS"

make clean
make


%install
[ -d %{buildroot} ] && rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
mkdir -p %{buildroot}%{_sbindir}
install -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/
install -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/%{name}.conf.default
install -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
install -m 755 %{SOURCE3} %{buildroot}%{_sbindir}/
install -m 755 %{SOURCE4} %{buildroot}%{_sbindir}/
install -m 755 %{SOURCE5} %{buildroot}%{_sbindir}/
install -m 755 %{_builddir}/src/%{name} %{buildroot}%{_sbindir}/

%clean
(cd %{_builddir}; make clean)

%files
%defattr(755,root,root,-)
%config %attr(644,root,root) %{_sysconfdir}/%{name}.conf
%config %attr(644,root,root) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/%{name}.conf.default

%{_sbindir}/%{name}
%{_sbindir}/frox_configure.pl
%{_sbindir}/frox_start.sh
%{_sbindir}/frox_stop.sh

%changelog
* Tue Apr 29 2014 <ychislov@trustwave.com> - 0.7.23-1
- Init release

