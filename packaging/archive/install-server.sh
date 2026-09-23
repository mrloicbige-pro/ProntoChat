#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this installer as root: sudo ./install.sh" >&2
    exit 1
fi

if ! command -v dnf >/dev/null 2>&1; then
    printf '%s\n' "This prebuilt archive currently supports Fedora with dnf." >&2
    exit 1
fi

archive_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

printf '%s\n' "Installing ProntoChat server runtime dependencies..."
dnf install -y libwebsockets libsodium

install -D -m 0755 "$archive_dir/bin/chat-server" /usr/local/bin/chat-server
install -D -m 0644 \
    "$archive_dir/share/prontochat/systemd/chat-server.service" \
    /etc/systemd/system/chat-server.service

systemctl daemon-reload
systemctl enable chat-server.service
systemctl restart chat-server.service

printf '%s\n' "ProntoChat server installed and started."
systemctl --no-pager --full status chat-server.service
