%global debug_package %{nil}

Name:           monito
Version:        1.1.0
Release:        1%{?dist}
Summary:        Per-application Linux network traffic monitor
License:        MIT OR GPL-2.0-only
URL:            https://github.com/BraveRam/monito
Source0:        %{name}-%{version}.tar.gz
BuildArch:      x86_64

BuildRequires:  golang >= 1.26.2
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Monito records Linux network traffic by application and provides a terminal
dashboard for daily usage, transfer rates, and traffic categories. The package
includes the collector daemon and its systemd service.

%prep
%autosetup -n %{name}-%{version}

%build
%make_build build VERSION=%{version}

%check
go test ./...

%install
install -Dpm 0755 bin/monito %{buildroot}%{_bindir}/monito
install -Dpm 0755 bin/monitod %{buildroot}%{_bindir}/monitod
install -Dpm 0644 dist/systemd/monito.service %{buildroot}%{_unitdir}/monito.service
sed -i 's#/usr/local/bin/monitod#%{_bindir}/monitod#' \
    %{buildroot}%{_unitdir}/monito.service

%post
%systemd_post monito.service

%preun
%systemd_preun monito.service

%postun
%systemd_postun_with_restart monito.service

%files
%license LICENSE LICENSE-GPL-2.0
%{_bindir}/monito
%{_bindir}/monitod
%{_unitdir}/monito.service

%changelog
* Sat Oct 17 2026 Monito contributors - 1.1.0-1
- Add Ubuntu DEB packaging alongside Fedora RPM releases

* Sat Oct 17 2026 Monito contributors - 1.0.1-1
- Use decimal units for traffic sizes and rates
- Convert First Seen timestamps to UTC before displaying them
- Avoid rounding partial app attribution to 100.0 percent

* Sat Oct 17 2026 Monito contributors - 1.0.0-1
- Initial RPM release
