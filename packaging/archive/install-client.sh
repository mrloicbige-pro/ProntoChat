#!/bin/sh

set -eu

archive_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix="$HOME/.local"
unit_dir="$HOME/.config/systemd/user"

install -D -m 0755 "$archive_dir/bin/chat" "$prefix/bin/chat"
install -D -m 0755 "$archive_dir/bin/chatd" "$prefix/bin/chatd"
install -D -m 0644 \
    "$archive_dir/share/chat/systemd/chatd.service" \
    "$unit_dir/chatd.service"

systemctl --user daemon-reload

printf '%s\n' "ProntoChat client installed in $prefix/bin."
printf '%s\n' "Create an identity with: chat init <username>"
printf '%s\n' "Then start the daemon with: systemctl --user enable --now chatd.service"
