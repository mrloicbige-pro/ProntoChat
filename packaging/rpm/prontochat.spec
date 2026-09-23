Name:           prontochat
Version:        0.1.1
Release:        2%{?dist}
Summary:        Terminal P2P encrypted messenger
License:        LicenseRef-Project-Specific
URL:            https://github.com/mrloicbige-pro/ProntoChat
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  glib2-devel
BuildRequires:  libnice-devel
BuildRequires:  libsodium-devel
BuildRequires:  libwebsockets-devel
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  systemd-rpm-macros

Requires:       glib2
Requires:       libnice
Requires:       libsodium
Requires:       libwebsockets
Conflicts:      ppp

%description
ProntoChat provides the chat command and per-user chatd daemon for authenticated,
end-to-end encrypted one-to-one terminal conversations over ICE, STUN, and TURN.

%prep
%autosetup -n ProntoChat-%{version}

%build
%cmake -G Ninja -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
%cmake_build

%install
%cmake_install
install -Dpm 0644 packaging/systemd/chatd.service \
    %{buildroot}%{_userunitdir}/chatd.service
rm -f %{buildroot}%{_datadir}/chat/systemd/chatd.service

%files
%{_bindir}/chat
%{_bindir}/chatd
%{_userunitdir}/chatd.service
%{_datadir}/chat/launchd/chatd.plist

%post
%systemd_user_post chatd.service

%preun
%systemd_user_preun chatd.service

%postun
%systemd_user_postun_with_restart chatd.service

%changelog
* Sat Sep 19 2026 ProntoChat maintainers <maintainers@example.invalid> - 0.1.0-2
- Install the daemon as a discoverable systemd user service
- Declare the command-name conflict with Fedora's ppp package

* Fri Sep 18 2026 ProntoChat maintainers <maintainers@example.invalid> - 0.1.0-1
- Initial package
