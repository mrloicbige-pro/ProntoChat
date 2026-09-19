# chat

Terminal P2P encrypted messenger in C.

See [spec.md](spec.md) for the project specification and implementation order.

## Build

Dependencies on Fedora:

```bash
sudo dnf install \
    gcc \
    cmake \
    pkgconf-pkg-config \
    glib2-devel \
    libnice-devel \
    libsodium-devel \
    libwebsockets-devel
```

Dependencies on macOS:

```bash
brew install \
    cmake \
    pkg-config \
    glib \
    libnice \
    libsodium \
    libwebsockets
```

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Local ICE and end-to-end test suite:

```bash
cmake -S . -B build-network -DCHAT_ENABLE_NETWORK_TESTS=ON
cmake --build build-network
ctest --test-dir build-network --output-on-failure
```

These tests start temporary `chat-server` and `chatd` processes and exercise
direct ICE, encrypted messaging, offline peers, identity mismatch handling, and
control-server loss. They need local socket and UDP permissions, so they remain
disabled in the default build.

Development build with sanitizers:

```bash
cmake -S . -B build-asan -DCHAT_ENABLE_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan
```

## Install

User-local install:

```bash
cmake --install build --prefix "$HOME/.local"
```

This installs `chat` and `chatd`. The development `chat-server` is intentionally
not installed as part of the client package.

## Usage

```bash
chat init alex
chat status
chat nathan
chat fingerprint nathan
```

`chat fingerprint <username>` prints the locally pinned identity fingerprint for
an existing contact.

For local multi-user testing on one machine, give each daemon its own config
directory and IPC socket:

```bash
CHAT_CONFIG_DIR=/tmp/chat-alex CHAT_SOCKET_PATH=/tmp/chat-alex.sock chatd
CHAT_CONFIG_DIR=/tmp/chat-nathan CHAT_SOCKET_PATH=/tmp/chat-nathan.sock chatd
```

TURN relay mode requires a real TURN server, for example coturn, and matching
`turn_server`, `turn_port`, `turn_username`, and `turn_password` entries in each
test user's `config.toml`. Add `ice_force_relay = "true"` to prevent direct
candidates from being selected while validating TURN.

## User Service

Fedora/systemd user service:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp "$HOME/.local/share/chat/systemd/chatd.service" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now chatd.service
```

macOS LaunchAgent, assuming `cmake --install build --prefix /usr/local`:

```bash
mkdir -p "$HOME/Library/LaunchAgents"
cp /usr/local/share/chat/launchd/chatd.plist "$HOME/Library/LaunchAgents/dev.chat.chatd.plist"
launchctl load "$HOME/Library/LaunchAgents/dev.chat.chatd.plist"
```

## Packaging

The Fedora RPM manifest is in `packaging/rpm/prontochat.spec`. After publishing
the `v0.1.0` source tag, build it with the standard Fedora RPM toolchain.

The Homebrew Formula is in `packaging/homebrew/prontochat.rb`. Copy it into a
tap as `Formula/prontochat.rb` after publishing the same source tag, then run:

```bash
brew install <tap>/prontochat
brew services start <tap>/prontochat
```
