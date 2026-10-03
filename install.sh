#!/usr/bin/env bash
#
# PortBridge installer.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Nima786/portbridge/main/install.sh)
#
# Downloads the prebuilt engine for this machine, installs the menu, and opens it.
# Falls back to building from source when a download is not possible, which is
# common on servers with restricted outbound access.

set -uo pipefail

REPO=Nima786/portbridge
BIN=/usr/local/bin/portbridge
MENU=/usr/local/bin/portbridge-menu
FIREWALL=/usr/local/bin/portbridge-firewall
TUNE=/usr/local/bin/portbridge-tune
UNIT=/etc/systemd/system/portbridge@.service
AGENT_UNIT=/etc/systemd/system/portbridge-agent.service
CONF_DIR=/etc/portbridge/tunnels

if [ -t 1 ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
else
    B=''; DIM=''; R=''; RED=''; GREEN=''; YELLOW=''
fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s\n' "${GREEN}$*${R}"; }
warn() { printf '%s\n' "${YELLOW}$*${R}"; }
die()  { printf '%s\n' "${RED}$*${R}" >&2; exit 1; }
step() { printf '\n%s\n' "${B}==> $*${R}"; }

[ "$(id -u)" -eq 0 ] || die "Please run this as root."

FORCE=no
NOMENU=no
VERSION_ASKED=""
while [ $# -gt 0 ]; do
    case "$1" in
        --force | --reinstall) FORCE=yes ;;
        --no-menu) NOMENU=yes ;;
        --version)
            [ $# -ge 2 ] || die "--version needs a value, for example --version v0.4.6"
            VERSION_ASKED=$2
            shift
            ;;
        --version=*) VERSION_ASKED=${1#--version=} ;;
        -h | --help)
            cat <<'EOF'
Installs or updates PortBridge, then opens the menu.

Running it again is also how you update: it checks for a newer version, and
goes straight to the menu if there is nothing to do.

  --force            reinstall even if it is already up to date
  --version vX.Y.Z   install that release instead of the latest
  --no-menu          do not open the menu afterwards
EOF
            exit 0
            ;;
        *) die "Unknown option: $1. Try --help." ;;
    esac
    shift
done
if [ -n "$VERSION_ASKED" ]; then
    case "$VERSION_ASKED" in
        v[0-9]*.[0-9]*.[0-9]*) ;;
        *) die "A version looks like v0.4.6, not '$VERSION_ASKED'." ;;
    esac
    case "$VERSION_ASKED" in
        *[!a-zA-Z0-9.+-]*) die "A version looks like v0.4.6, not '$VERSION_ASKED'." ;;
    esac
    FORCE=yes
fi

open_menu_and_exit() {
    if [ "$NOMENU" = yes ]; then
        exit 0
    fi
    if [ -t 0 ] && [ -x "$MENU" ]; then
        # exec replaces this process, so the exit trap would never run.
        [ -n "${TMP-}" ] && rm -rf "$TMP"
        exec "$MENU"
    fi
    say ""
    say "Open the menu with: ${B}portbridge-menu${R}"
    exit 0
}

# ------------------------------------------------------------------ environment

step "Checking this server"

[ -d /run/systemd/system ] || die "This needs systemd, which this server does not appear to use."

case "$(uname -s)" in
    Linux) ;;
    *) die "PortBridge runs on Linux only." ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "Unsupported processor type: $(uname -m). Only 64-bit Intel and ARM are built." ;;
esac
say "  Linux, $ARCH, systemd present"

for t in curl tar; do
    command -v "$t" >/dev/null 2>&1 || MISSING="${MISSING-} $t"
done
if [ -n "${MISSING-}" ]; then
    say "  Installing:${MISSING}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq || true
        # shellcheck disable=SC2086
        apt-get install -y -qq $MISSING || die "Could not install:${MISSING}"
    elif command -v dnf >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        dnf install -y -q $MISSING || die "Could not install:${MISSING}"
    elif command -v yum >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        yum install -y -q $MISSING || die "Could not install:${MISSING}"
    else
        die "Please install${MISSING} and run this again."
    fi
fi

command -v iptables >/dev/null 2>&1 || warn "  iptables is missing, so tunnel ports cannot be locked down. Install it to enable that."

# ------------------------------------------------------------------- get engine

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/stage"
mkdir -p "$STAGE"

latest_tag() {
    curl -fsSL --max-time 15 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
        sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1
}

# fetch_release <tag> - downloads the prebuilt archive and checks it against the
# checksums published with the release before anything in it is trusted.
fetch_release() {
    local tag=$1 name url want got
    [ -n "$tag" ] || return 1
    name="portbridge_${tag#v}_linux_${ARCH}.tar.gz"
    url="https://github.com/$REPO/releases/download/$tag"
    curl -fsSL --max-time 120 -o "$TMP/pb.tar.gz" "$url/$name" || return 1
    if ! curl -fsSL --max-time 30 -o "$TMP/checksums.txt" "$url/checksums.txt"; then
        warn "  Could not get the release's checksums, so the download cannot be verified."
        return 1
    fi
    want=$(awk -v n="./$name" -v m="$name" '$2 == n || $2 == m {print $1; exit}' "$TMP/checksums.txt")
    got=$(sha256sum "$TMP/pb.tar.gz" | awk '{print $1}')
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        warn "  The download does not match its published checksum. Not using it."
        return 1
    fi
    mkdir -p "$TMP/rel"
    tar -xzf "$TMP/pb.tar.gz" -C "$TMP/rel" || return 1
    [ -f "$TMP/rel/portbridge" ] || return 1
    return 0
}

# build_from_source <tag> - builds exactly the release asked for. It never falls
# back to whatever is on the main branch today, which could be a half-finished
# change that was never released.
build_from_source() {
    local tag=$1
    [ -n "$tag" ] || return 1
    command -v go >/dev/null 2>&1 || return 1
    say "  Building $tag from source with $(go version | awk '{print $3}')"
    curl -fsSL --max-time 60 -o "$TMP/src.tar.gz" "https://github.com/$REPO/archive/refs/tags/$tag.tar.gz" || return 1
    mkdir -p "$TMP/src"
    tar -xzf "$TMP/src.tar.gz" -C "$TMP/src" || return 1
    local dir
    dir=$(find "$TMP/src" -maxdepth 1 -mindepth 1 -type d | head -1)
    [ -n "$dir" ] || return 1
    mkdir -p "$TMP/rel"
    ( cd "$dir" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$tag" -o "$TMP/rel/portbridge" . ) || return 1
    # The scripts and service files come from the same source.
    mkdir -p "$TMP/rel/scripts" "$TMP/rel/packaging"
    cp "$dir"/scripts/* "$TMP/rel/scripts/" || return 1
    cp "$dir"/packaging/*.service "$TMP/rel/packaging/" || return 1
    return 0
}

# Running this command again is the intended way to update. But when nothing has
# changed there is no reason to download and reinstall everything, and whoever
# ran it again almost certainly just wants the menu.
INSTALLED=""
if [ -x "$BIN" ] && [ -x "$MENU" ] && [ -f "$UNIT" ]; then
    INSTALLED=$("$BIN" version 2>/dev/null)
fi

WANTED=$VERSION_ASKED
if [ -z "$WANTED" ] && [ -n "$INSTALLED" ] && [ "$FORCE" = no ]; then
    step "Checking for a newer version"
    WANTED=$(latest_tag)
    if [ -z "$WANTED" ]; then
        say "  Cannot reach GitHub right now, so keeping what is already here ($INSTALLED)"
        open_menu_and_exit
    fi
    if [ "$WANTED" = "$INSTALLED" ]; then
        ok "  PortBridge $INSTALLED is already installed and up to date."
        say "  ${DIM}Opening the menu. You can also just run: portbridge-menu${R}"
        open_menu_and_exit
    fi
    say "  You have $INSTALLED, and $WANTED is available. Updating."
fi

step "Fetching PortBridge"
[ -n "$WANTED" ] || WANTED=$(latest_tag)
[ -n "$WANTED" ] || die "Could not find out which version is the latest. This server may not be able to reach GitHub.
Try again later, or name a version yourself with --version vX.Y.Z"
say "  Release $WANTED"
if fetch_release "$WANTED"; then
    ok "  Downloaded a prebuilt copy, checksum verified"
elif build_from_source "$WANTED"; then
    ok "  Built from source"
else
    die "Could not download or build PortBridge $WANTED.
This server may not be able to reach GitHub. Options:
  - install Go (apt install golang-go) and run this again, or
  - copy the portbridge binary across by hand to $BIN"
fi

# ------------------------------------------------------------------- stage it all
#
# Everything is gathered and checked before anything on this server is replaced,
# so a failure half way never leaves a new engine next to an old menu.

step "Checking what was downloaded"

for s in portbridge-menu portbridge-firewall portbridge-tune; do
    [ -f "$TMP/rel/scripts/$s" ] || die "The download is missing $s."
    bash -n "$TMP/rel/scripts/$s" || die "$s did not pass a syntax check, so it will not be installed."
    cp "$TMP/rel/scripts/$s" "$STAGE/$s"
done
[ -f "$TMP/rel/packaging/portbridge@.service" ] || die "The download is missing the service template."
cp "$TMP/rel/packaging/portbridge@.service" "$STAGE/portbridge@.service"
[ -f "$TMP/rel/packaging/portbridge-agent.service" ] && cp "$TMP/rel/packaging/portbridge-agent.service" "$STAGE/portbridge-agent.service"
cp "$TMP/rel/portbridge" "$STAGE/portbridge"
chmod 755 "$STAGE/portbridge"
"$STAGE/portbridge" version >/dev/null 2>&1 || die "The new engine does not run on this server, so nothing was changed."
say "  Engine $("$STAGE/portbridge" version), scripts and service files look sound"

step "Installing"

install -m 755 "$STAGE/portbridge" "$BIN"
install -m 755 "$STAGE/portbridge-menu" "$MENU"
install -m 755 "$STAGE/portbridge-firewall" "$FIREWALL"
install -m 755 "$STAGE/portbridge-tune" "$TUNE"
install -m 644 "$STAGE/portbridge@.service" "$UNIT"
[ -f "$STAGE/portbridge-agent.service" ] && install -m 644 "$STAGE/portbridge-agent.service" "$AGENT_UNIT"

mkdir -p "$CONF_DIR" /etc/portbridge/agents /run/portbridge
chmod 700 /etc/portbridge "$CONF_DIR" /etc/portbridge/agents
systemctl daemon-reload

# Tunnels made by an older version may have no firewall setting at all, which
# means "on": their port is locked to the other server's address. That is the
# safe default, but it is a change for anyone whose link arrives from somewhere
# else, a CDN for instance, so it is pointed out rather than left to be found.
NOFIREWALL=""
for f in "$CONF_DIR"/*.conf; do
    [ -e "$f" ] || continue
    grep -qE '^[[:space:]]*firewall[[:space:]]*=' "$f" || NOFIREWALL="$NOFIREWALL $(basename "$f" .conf)"
done

# Existing tunnels keep working across an upgrade; restart them on the new engine.
step "Finishing up"
restarted=0
for f in "$CONF_DIR"/*.conf; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .conf)
    if systemctl is-enabled "portbridge@$n.service" >/dev/null 2>&1; then
        systemctl restart "portbridge@$n.service" && restarted=$((restarted + 1))
    fi
done
[ "$restarted" -gt 0 ] && say "  Restarted $restarted existing tunnel(s) on the new version"

if systemctl is-active portbridge-agent.service >/dev/null 2>&1; then
    systemctl restart portbridge-agent.service && say "  Restarted management agent on the new version"
fi

if [ -n "$NOFIREWALL" ]; then
    warn ""
    warn "  These tunnels had no firewall setting, so their port is now limited to the other"
    warn "  server's address:${NOFIREWALL}"
    warn "  If any of them is reached through a CDN, turn its firewall off in the menu"
    warn "  (Firewall -> Turn the firewall off for a tunnel)."
fi

ok "
PortBridge is installed."
say "
Open the menu any time with:  ${B}portbridge-menu${R}
"
say "${DIM}On your Iran server, choose 'Create a tunnel'. It gives you a code.${R}"
say "${DIM}Then on your foreign server, choose 'Join a tunnel' and paste that code.${R}"
say ""

if [ "$NOMENU" = no ] && [ -t 0 ]; then
    printf '%s' "Open the menu now? ${DIM}[Y/n]${R}: "
    read -r a || true
    case "$a" in
        [nN]*) exit 0 ;;
        *)
            # exec replaces this process, so the exit trap would never run.
            rm -rf "$TMP"
            exec "$MENU"
            ;;
    esac
fi
