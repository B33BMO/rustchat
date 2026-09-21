#!/bin/sh
# Renders docs/demo.gif.
#
#   sh docs/record-demo.sh
#
# Spins up a relay on loopback with throwaway keys, joins it as a second
# person via docs/demo-partner.py, and records one client with VHS. Nothing
# here touches a real relay or a real room key, and every key it generates is
# discarded when it finishes.
#
# Needs: vhs, ttyd, ffmpeg, python3, and a release build of rustchat.

set -eu

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

cd "$(dirname "$0")/.."

for tool in vhs ttyd ffmpeg python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done

BIN=${RUSTCHAT_BIN:-./target/release/rustchat}
RELAY_BIN=${RUSTCHAT_RELAY_BIN:-./target/release/rustchat-relay}
[ -x "$BIN" ] || die "no rustchat at $BIN — run: cargo build --release"
[ -x "$RELAY_BIN" ] || die "no rustchat-relay at $RELAY_BIN — run: cargo build --release"

# A hostname rather than a bare address, so the recording does not put
# somebody's real relay on the project's front page. Loopback either way.
DEMO_HOST=${DEMO_HOST:-relay.example.com}
DEMO_PORT=${DEMO_PORT:-7777}
if ! getent hosts "$DEMO_HOST" >/dev/null 2>&1; then
    die "$DEMO_HOST does not resolve. Add it to /etc/hosts:
       127.0.0.1 $DEMO_HOST
     or set DEMO_HOST=localhost to record without it."
fi

WORK=$(mktemp -d)
RELAY_PID=""
PARTNER_PID=""
cleanup() {
    if [ -n "$PARTNER_PID" ]; then kill "$PARTNER_PID" 2>/dev/null || true; fi
    if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

step "Generating throwaway keys"
"$BIN" relaykey > "$WORK/relaykey"
ACCESS=$(awk '/^Relay access key/{print $4}' "$WORK/relaykey")
AUTH=$(awk '/^  [0-9a-f]/{print $1}' "$WORK/relaykey")
ROOM=$("$BIN" keygen | awk '/^Room key/{print $3}')
if [ -z "$ACCESS" ] || [ -z "$AUTH" ] || [ -z "$ROOM" ]; then
    die "could not generate keys"
fi

# ws:// not wss://: this relay is on loopback with no TLS in front of it.
if [ "$DEMO_PORT" = "80" ]; then
    RELAY_URL="ws://$DEMO_HOST/ws"
else
    RELAY_URL="ws://$DEMO_HOST:$DEMO_PORT/ws"
fi
INVITE=$("$BIN" invite -r "$RELAY_URL" -a "$ACCESS" -k "$ROOM" 2>/dev/null)
[ -n "$INVITE" ] || die "could not build an invite"

step "Starting a relay on 127.0.0.1:$DEMO_PORT"
"$RELAY_BIN" --bind "127.0.0.1:$DEMO_PORT" --auth-key "$AUTH" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
i=0
until curl -fsS --max-time 2 "http://127.0.0.1:$DEMO_PORT/health" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 25 ] && { cat "$WORK/relay.log" >&2; die "the relay did not come up"; }
    sleep 0.2
done

step "Joining as the other person"
RUSTCHAT_INVITE="$INVITE" RUSTCHAT_BIN="$BIN" \
    python3 docs/demo-partner.py >"$WORK/partner.log" 2>&1 &
PARTNER_PID=$!
# The partner has to be in the room before recording starts, or its opening
# line lands in history rather than on screen.
i=0
until grep -q 'connected' "$WORK/partner.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && { cat "$WORK/partner.log" >&2; die "the other person never joined"; }
    sleep 0.2
done

step "Recording"
# rustchat must be on PATH for the tape's Require, and for the command it types.
PATH="$(cd "$(dirname "$BIN")" && pwd):$PATH" \
    RUSTCHAT_INVITE="$INVITE" \
    vhs docs/demo.tape

printf '\n'
step "Wrote docs/demo.gif ($(du -h docs/demo.gif | cut -f1))"
cat "$WORK/partner.log"
