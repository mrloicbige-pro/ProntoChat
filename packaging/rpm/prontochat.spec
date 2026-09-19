Name:           prontochat
Version:        0.1.0
Release:        1%{?dist}
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

Requires:       glib2
Requires:       libnice
Requires:       libsodium
Requires:       libwebsockets

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

%files
%{_bindir}/chat
%{_bindir}/chatd
%{_datadir}/chat/systemd/chatd.service
%{_datadir}/chat/launchd/chatd.plist

%changelog
* Fri Sep 18 2026 ProntoChat maintainers <maintainers@example.invalid> - 0.1.0-1
- Initial package
