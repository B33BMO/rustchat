#!/bin/sh
# Install and start a rustchat relay on a Linux box with systemd.
#
#   sudo sh deploy/setup-relay.sh --auth-key <64 hex chars> [--port 7777]
#
# The relay binds loopback only and speaks plain HTTP: put Cloudflare Tunnel,
# nginx or Caddy in front of it to terminate TLS. It is given the relay's
# *access* auth key, which lets it turn away clients that don't hold the access
# key. It is given no room keys at all, so it carries any number of rooms while
# being unable to read a single message in any of them.

set -eu

PORT=7777
AUTH_KEY=""
HISTORY=200
BIN_DEST=/usr/local/bin/rustchat-relay
ENV_FILE=/etc/rustchat-relay.env
UNIT_DEST=/etc/systemd/system/rustchat-relay.service
REPO="B33BMO/rustchat"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --auth-key) shift; [ $# -gt 0 ] || die "--auth-key needs a value"; AUTH_KEY="$1" ;;
        --port)     shift; [ $# -gt 0 ] || die "--port needs a value"; PORT="$1" ;;
        --history)  shift; [ $# -gt 0 ] || die "--history needs a value"; HISTORY="$1" ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" = "0" ] || die "run this with sudo"
[ -n "$AUTH_KEY" ] || die "pass --auth-key (get one from 'rustchat relaykey')"

# Validate before touching anything, so a typo doesn't leave a broken unit.
case "$AUTH_KEY" in
    *[!0-9a-fA-F]*) die "the auth key must be hex" ;;
esac
[ "${#AUTH_KEY}" = "64" ] || die "the auth key must be 64 hex characters (got ${#AUTH_KEY})"
case "$PORT" in
    ''|*[!0-9]*) die "--port must be a number" ;;
esac

command -v systemctl >/dev/null 2>&1 || die "this script needs systemd"

# --- binary -----------------------------------------------------------------
if [ -f ./target/release/rustchat-relay ]; then
    step "Installing the locally built relay"
    install -m 755 ./target/release/rustchat-relay "$BIN_DEST"
elif command -v rustchat-relay >/dev/null 2>&1 && [ "$(command -v rustchat-relay)" != "$BIN_DEST" ]; then
    step "Installing the relay already on PATH"
    install -m 755 "$(command -v rustchat-relay)" "$BIN_DEST"
elif [ -f "$BIN_DEST" ]; then
    step "Using the relay already at $BIN_DEST"
else
    step "Downloading the latest relay release"
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  target=x86_64-unknown-linux-musl ;;
        aarch64|arm64) target=aarch64-unknown-linux-musl ;;
        *) die "no prebuilt relay for $arch — build it with 'cargo build --release'" ;;
    esac
    tag=$(curl -fsSL --retry 3 --retry-delay 2 "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$tag" ] || die "could not find the latest release"
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    base="https://github.com/$REPO/releases/download/$tag"
    curl -fsSL --retry 3 --retry-delay 2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "could not fetch SHA256SUMS"
    asset="rustchat-relay-$target.tar.gz"
    curl -fsSL --retry 3 --retry-delay 2 "$base/$asset" -o "$tmp/$asset" || die "could not fetch $asset"
    expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
    [ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
    actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
    [ "$actual" = "$expected" ] || die "checksum mismatch for $asset — not installing"
    tar -xzf "$tmp/$asset" -C "$tmp"
    install -m 755 "$tmp/rustchat-relay" "$BIN_DEST"
fi

# --- config -----------------------------------------------------------------
step "Writing $ENV_FILE"
# Created private up front: this file holds the room's auth key.
umask 077
cat > "$ENV_FILE" <<EOF
# rustchat relay configuration. Managed by deploy/setup-relay.sh.
#
# This is the relay's ACCESS auth key. It decides who may connect. It is not a
# room key, and no room key is stored here: the relay routes rooms by a one-way
# id and cannot read any of them.
RUSTCHAT_AUTH_KEY=$AUTH_KEY
RUSTCHAT_BIND=127.0.0.1:$PORT
RUSTCHAT_HISTORY=$HISTORY
RUSTCHAT_MAX_CONNS=200
RUSTCHAT_MAX_ROOMS=64
EOF
chmod 600 "$ENV_FILE"

step "Writing $UNIT_DEST"
unit_src=$(dirname "$0")/rustchat-relay.service
[ -f "$unit_src" ] || die "could not find rustchat-relay.service next to this script"
install -m 644 "$unit_src" "$UNIT_DEST"

step "Starting the service"
systemctl daemon-reload
systemctl enable rustchat-relay >/dev/null 2>&1 || true
systemctl restart rustchat-relay

# Give it a moment, then confirm it is actually up rather than just launched.
sleep 1
if ! systemctl is-active --quiet rustchat-relay; then
    printf '\n'
    systemctl status rustchat-relay --no-pager -l | tail -20
    die "the relay did not stay running"
fi

health=$(curl -fsS --max-time 5 "http://127.0.0.1:$PORT/health" 2>/dev/null || true)
[ -n "$health" ] || die "the relay is running but not answering on port $PORT"

printf '\n==> Relay is up on 127.0.0.1:%s\n' "$PORT"
printf '    health: %s\n\n' "$health"
cat <<EOF
Next, expose it. For Cloudflare Tunnel, add this to your ingress list
(above the catch-all rule):

  - hostname: <your.hostname>
    service: http://localhost:$PORT

then create the DNS route and restart the tunnel:

  cloudflared tunnel route dns <tunnel> <your.hostname>
  sudo systemctl restart cloudflared

Then hand people an invite, which bundles the relay address with the access
key and a room key into one value to paste. On any machine with rustchat:

  rustchat keygen                       (prints a room key)
  rustchat invite --relay <your.hostname> --access-key <access key> \
                  --room-key <that room key>

Anyone can also just run rustchat and enter the parts by hand. Any number of
rooms work on this relay without configuring it again.

Logs:    journalctl -u rustchat-relay -f
Restart: sudo systemctl restart rustchat-relay
EOF
