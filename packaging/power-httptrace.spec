Name:           power-httptrace
Version:        1.0.0
Release:        1%{?dist}
Summary:        HTTP full-chain collector based on eBPF
License:        Proprietary

%global srcname power-ebpf
%global install_root /app/soft/power-httptrace
%global log_root /app/log/power-httptrace

Source0:        %{srcname}-%{version}.tar.gz

BuildRequires:  go
BuildRequires:  make
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  systemd-rpm-macros
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires:       bash
Requires:       logrotate

%description
power-httptrace is an eBPF-based HTTP request/response collector.

%prep
%autosetup -n %{srcname}-%{version}

%build
%ifarch x86_64
make build-amd64
%else
%ifarch aarch64
make build-arm64
%else
echo "unsupported target arch: %{_arch}"
exit 1
%endif
%endif

%install
rm -rf %{buildroot}

install -d %{buildroot}%{install_root}
install -d %{buildroot}%{install_root}/bin
install -d %{buildroot}%{log_root}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d %{buildroot}%{_sysconfdir}/logrotate.d

%ifarch x86_64
install -m 0755 bin/httptrace-linux-amd64 %{buildroot}%{install_root}/bin/httptrace
%else
%ifarch aarch64
install -m 0755 bin/httptrace-linux-arm64 %{buildroot}%{install_root}/bin/httptrace
%else
echo "unsupported target arch: %{_arch}"
exit 1
%endif
%endif

install -m 0644 packaging/SOURCES/power-httptrace.service %{buildroot}%{_unitdir}/power-httptrace.service
install -m 0644 packaging/SOURCES/power-httptrace.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/power-httptrace
install -m 0644 packaging/SOURCES/power-httptrace.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/power-httptrace

%post
%systemd_post power-httptrace.service

%preun
%systemd_preun power-httptrace.service

%postun
%systemd_postun_with_restart power-httptrace.service

%files
%dir %{install_root}
%dir %{install_root}/bin
%attr(0755,root,root) %{install_root}/bin/httptrace
%dir %{log_root}
%config(noreplace) %{_sysconfdir}/sysconfig/power-httptrace
%config(noreplace) %{_sysconfdir}/logrotate.d/power-httptrace
%{_unitdir}/power-httptrace.service

%changelog
# By POWER