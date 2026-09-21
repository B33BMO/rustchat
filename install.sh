#!/bin/sh
# rustchat installer.
#
#   curl -fsSL https://raw.githubusercontent.com/B33BMO/rustchat/main/install.sh | sh
#
# Downloads the right prebuilt binary for this machine, checks it against the
# published SHA256SUMS, and puts it somewhere on your PATH. Falls back to
# building from source when there is no prebuilt binary for your platform.
#
# Environment:
#   RUSTCHAT_VERSION      tag to install (default: the latest release)
#   RUSTCHAT_INSTALL_DIR  where to put the binary
#   RUSTCHAT_RELAY=1      also install rustchat-relay (for hosting a room)
#
# Flags: --relay, --version <tag>, --dir <path>, --uninstall, --help

set -eu

REPO="B33BMO/rustchat"
# Overridable so the installer can be exercised against a local fixture, and so
# a private mirror can serve the assets instead of GitHub.
DOWNLOAD_BASE="${RUSTCHAT_DOWNLOAD_BASE:-}"
WANT_RELAY="${RUSTCHAT_RELAY:-}"
VERSION="${RUSTCHAT_VERSION:-}"
INSTALL_DIR="${RUSTCHAT_INSTALL_DIR:-}"
UNINSTALL=""

# --- output -----------------------------------------------------------------
# Only colorize when stdout is a terminal; piping through `sh` often isn't.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
    YLW=$(printf '\033[33m'); RST=$(printf '\033[0m')
else
    B=''; DIM=''; RED=''; YLW=''; RST=''
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$B" "$RST" "$*"; }
note() { printf '    %s%s%s\n' "$DIM" "$*" "$RST"; }
warn() { printf '%swarning:%s %s\n' "$YLW" "$RST" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
rustchat installer

  --relay            also install rustchat-relay (only needed to host a room)
  --version <tag>    install a specific release instead of the latest
  --dir <path>       install into <path>
  --uninstall        remove installed rustchat binaries
  --help             show this

EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --relay)     WANT_RELAY=1 ;;
        --version)   shift; [ $# -gt 0 ] || die "--version needs a tag"; VERSION="$1" ;;
        --dir)       shift; [ $# -gt 0 ] || die "--dir needs a path"; INSTALL_DIR="$1" ;;
        --uninstall) UNINSTALL=1 ;;
        --help|-h)   usage; exit 0 ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

have() { command -v "$1" >/dev/null 2>&1; }

# A single scratch directory with a single trap; a second `trap ... EXIT`
# elsewhere would silently replace this one and leak the first directory.
TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# --- where to install -------------------------------------------------------
resolve_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        printf '%s' "$INSTALL_DIR"; return
    fi
    # Prefer a system path when we can already write it, but never escalate
    # with sudo on our own — a piped-in script should not be asking for root.
    if [ -w /usr/local/bin ] 2>/dev/null; then
        printf '/usr/local/bin'; return
    fi
    printf '%s/.local/bin' "$HOME"
}

# --- uninstall --------------------------------------------------------------
if [ -n "$UNINSTALL" ]; then
    removed=""
    for dir in "$(resolve_install_dir)" /usr/local/bin "$HOME/.local/bin"; do
        for bin in rustchat rustchat-relay; do
            if [ -f "$dir/$bin" ]; then
                rm -f "$dir/$bin" && removed="$removed $dir/$bin"
            fi
        done
    done
    if [ -n "$removed" ]; then
        step "Removed:"
        for r in $removed; do note "$r"; done
    else
        say "Nothing to remove."
    fi
    say ""
    say "Your vault was left alone. To delete it too:"
    case "$(uname -s)" in
        Darwin) note "rm -rf ~/Library/Application\\ Support/rustchat" ;;
        *)      note "rm -rf \${XDG_CONFIG_HOME:-\$HOME/.config}/rustchat" ;;
    esac
    exit 0
fi

# --- platform ---------------------------------------------------------------
detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64)  printf 'x86_64-unknown-linux-musl' ;;
                aarch64|arm64) printf 'aarch64-unknown-linux-musl' ;;
                *) return 1 ;;
            esac ;;
        Darwin)
            case "$arch" in
                arm64)  printf 'aarch64-apple-darwin' ;;
                x86_64) printf 'x86_64-apple-darwin' ;;
                *) return 1 ;;
            esac ;;
        MINGW*|MSYS*|CYGWIN*)
            die "Windows isn't supported by this installer yet. Under WSL, run it again inside your Linux shell." ;;
        *) return 1 ;;
    esac
}

fetch() {
    # $1 url, $2 destination ("-" for stdout).
    #
    # Retries on transient failures. Without this, a single 5xx from a CDN --
    # which GitHub serves fairly readily just after a release is published --
    # looks identical to a missing asset, and sends everyone down the
    # compile-from-source path for no reason.
    if have curl; then
        if [ "$2" = "-" ]; then
            curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "$1"
        else
            curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "$1" -o "$2"
        fi
    elif have wget; then
        if [ "$2" = "-" ]; then
            wget -q --tries=3 --waitretry=2 -O- "$1"
        else
            wget -q --tries=3 --waitretry=2 -O "$2" "$1"
        fi
    else
        die "need curl or wget"
    fi
}

sha256_of() {
    if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
    elif have shasum;   then shasum -a 256 "$1" | cut -d' ' -f1
    else return 1
    fi
}

latest_version() {
    fetch "https://api.github.com/repos/$REPO/releases/latest" - 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1
}

# --- build from source ------------------------------------------------------
build_from_source() {
    reason="$1"
    warn "$reason"
    have cargo || die "no prebuilt binary for this platform and no cargo to build one.
       Install Rust from https://rustup.rs and run this again."

    step "Building from source with cargo"
    have git || die "need git to build from source"
    git clone --depth 1 "https://github.com/$REPO" "$TMP/src" >/dev/null 2>&1 \
        || die "could not clone https://github.com/$REPO"
    ( cd "$TMP/src" && cargo build --release --locked ) || die "the build failed"

    dir=$(resolve_install_dir)
    mkdir -p "$dir"
    install_binary "$TMP/src/target/release/rustchat" "$dir/rustchat"
    if [ -n "$WANT_RELAY" ]; then
        install_binary "$TMP/src/target/release/rustchat-relay" "$dir/rustchat-relay"
    fi
    finish "$dir"
    exit 0
}

# Install atomically, so a half-written binary never ends up on PATH — and so
# replacing a running copy doesn't fail with "text file busy".
install_binary() {
    src="$1"; dest="$2"
    cp "$src" "$dest.new" || die "could not write to $(dirname "$dest") — try --dir ~/.local/bin"
    chmod 755 "$dest.new"
    mv -f "$dest.new" "$dest"
    note "installed $dest"
}

finish() {
    dir="$1"
    say ""
    step "Done."
    case ":$PATH:" in
        *":$dir:"*)
            say ""
            say "  Run ${B}rustchat${RST} to start."
            ;;
        *)
            warn "$dir is not on your PATH."
            say ""
            say "Add it, then reopen your shell:"
            case "$(basename "${SHELL:-sh}")" in
                zsh)  note "echo 'export PATH=\"$dir:\$PATH\"' >> ~/.zshrc" ;;
                fish) note "fish_add_path $dir" ;;
                *)    note "echo 'export PATH=\"$dir:\$PATH\"' >> ~/.bashrc" ;;
            esac
            say ""
            say "  Or run it directly: ${B}$dir/rustchat${RST}"
            ;;
    esac
    say ""
    if [ -n "$WANT_RELAY" ]; then
        say "To run a relay:"
        note "rustchat relaykey            # prints an access key + the relay's auth key"
        note "rustchat-relay --auth-key <auth key from above>"
        say ""
        say "It carries any number of rooms; no per-room configuration."
        say ""
    fi
}

# --- main -------------------------------------------------------------------
say ""
say "  ${B}rustchat${RST} ${DIM}— an encrypted TUI chatroom${RST}"
say ""

target=$(detect_target) || build_from_source "no prebuilt binary for $(uname -s)/$(uname -m)."

if [ -z "$VERSION" ]; then
    step "Looking up the latest release"
    VERSION=$(latest_version || true)
    [ -n "$VERSION" ] || build_from_source "could not reach the GitHub releases API."
fi
note "version $VERSION · $target"

if [ -n "$DOWNLOAD_BASE" ]; then
    base="$DOWNLOAD_BASE"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi

# The checksum file covers every asset in the release.
step "Downloading checksums"
if ! fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
    build_from_source "could not fetch SHA256SUMS for $VERSION (missing, or the download failed); not installing an unverified binary."
fi

binaries="rustchat"
[ -n "$WANT_RELAY" ] && binaries="rustchat rustchat-relay"

for bin in $binaries; do
    asset="$bin-$target.tar.gz"
    step "Downloading $asset"
    if ! fetch "$base/$asset" "$TMP/$asset" 2>/dev/null; then
        build_from_source "could not fetch $asset (missing, or the download failed)."
    fi

    expected=$(grep " $asset\$" "$TMP/SHA256SUMS" 2>/dev/null | cut -d' ' -f1 || true)
    [ -n "$expected" ] || die "$asset is missing from SHA256SUMS — refusing to install it."

    actual=$(sha256_of "$TMP/$asset") \
        || die "no sha256sum or shasum available to verify the download."
    if [ "$actual" != "$expected" ]; then
        die "checksum mismatch for $asset.
       expected $expected
       got      $actual
       Not installing. This could be a corrupted download — or tampering."
    fi
    note "checksum ok"

    tar -xzf "$TMP/$asset" -C "$TMP" || die "could not unpack $asset"
    [ -f "$TMP/$bin" ] || die "$asset did not contain $bin"
done

dir=$(resolve_install_dir)
mkdir -p "$dir" || die "could not create $dir"
step "Installing to $dir"
for bin in $binaries; do
    install_binary "$TMP/$bin" "$dir/$bin"
done

# Make sure what we installed actually runs here before claiming success.
if ! "$dir/rustchat" --version >/dev/null 2>&1; then
    die "the installed binary does not run on this machine.
       Try building from source: cargo install --git https://github.com/$REPO rustchat"
fi

finish "$dir"
