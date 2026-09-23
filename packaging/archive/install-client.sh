#!/bin/sh

set -eu

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "Run the client installer without sudo: ./install.sh <username>" >&2
    exit 1
fi

archive_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix="$HOME/.local"
unit_dir="$HOME/.config/systemd/user"
config_dir=${CHAT_CONFIG_DIR:-"${XDG_CONFIG_HOME:-"$HOME/.config"}/chat"}
chat_bin="$prefix/bin/chat"
username=${1:-}

if [ "$#" -gt 1 ]; then
    printf '%s\n' "Usage: ./install.sh [username]" >&2
    exit 1
fi

if ! command -v dnf >/dev/null 2>&1; then
    printf '%s\n' "This prebuilt archive currently supports Fedora with dnf." >&2
    exit 1
fi

printf '%s\n' "Installing ProntoChat runtime dependencies..."
sudo dnf install -y glib2 libnice libsodium libwebsockets

install -D -m 0755 "$archive_dir/bin/chat" "$prefix/bin/chat"
install -D -m 0755 "$archive_dir/bin/chatd" "$prefix/bin/chatd"
install -D -m 0644 \
    "$archive_dir/share/chat/systemd/chatd.service" \
    "$unit_dir/chatd.service"

export PATH="$prefix/bin:$PATH"
path_line='export PATH="$HOME/.local/bin:$PATH"'
if [ ! -f "$HOME/.bashrc" ] || ! grep -Fqx "$path_line" "$HOME/.bashrc"; then
    printf '\n%s\n' "$path_line" >> "$HOME/.bashrc"
fi

if [ -f "$config_dir/config.toml" ]; then
    "$chat_bin" config server wss://pronto-chat.duckdns.org
else
    if [ -z "$username" ]; then
        if [ -t 0 ]; then
            printf '%s' "Choose a username: "
            IFS= read -r username
        else
            printf '%s\n' "A username is required: ./install.sh <username>" >&2
            exit 1
        fi
    fi
    "$chat_bin" init "$username"
fi

systemctl --user daemon-reload
systemctl --user enable chatd.service
systemctl --user restart chatd.service

attempt=0
while [ "$attempt" -lt 10 ]; do
    if "$chat_bin" status >/dev/null 2>&1; then
        printf '%s\n' "ProntoChat is installed and chatd is running."
        "$chat_bin" status
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done

printf '%s\n' "ProntoChat is installed, but chatd did not become ready." >&2
printf '%s\n' "Inspect it with: journalctl --user -u chatd.service" >&2
exit 1
