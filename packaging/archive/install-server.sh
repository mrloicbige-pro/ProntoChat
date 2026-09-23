#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this installer as root: sudo ./install.sh" >&2
    exit 1
fi

archive_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -D -m 0755 "$archive_dir/bin/chat-server" /usr/local/bin/chat-server
install -D -m 0644 \
    "$archive_dir/share/prontochat/systemd/chat-server.service" \
    /etc/systemd/system/chat-server.service

systemctl daemon-reload
systemctl enable --now chat-server.service

printf '%s\n' "ProntoChat server installed and started."
printf '%s\n' "Check it with: systemctl status chat-server.service"
