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
UNIT=/etc/systemd/system/portbridge@.service
CONF_DIR=/etc/portbridge/tunnels
RAW="https://raw.githubusercontent.com/$REPO/main"

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
        apt-get update -qq && apt-get install -y -qq $MISSING || die "Could not install:${MISSING}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q $MISSING || die "Could not install:${MISSING}"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q $MISSING || die "Could not install:${MISSING}"
    else
        die "Please install${MISSING} and run this again."
    fi
fi

command -v iptables >/dev/null 2>&1 || warn "  iptables is missing, so tunnel ports cannot be locked down. Install it to enable that."

# ------------------------------------------------------------------- get engine

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch_release() {
    local tag url
    tag=$(curl -fsSL --max-time 20 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
        sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)
    [ -n "$tag" ] || return 1
    url="https://github.com/$REPO/releases/download/$tag/portbridge_${tag#v}_linux_${ARCH}.tar.gz"
    say "  Found release $tag"
    curl -fsSL --max-time 120 -o "$TMP/pb.tar.gz" "$url" || return 1
    tar -xzf "$TMP/pb.tar.gz" -C "$TMP" || return 1
    [ -f "$TMP/portbridge" ] || return 1
    return 0
}

build_from_source() {
    command -v go >/dev/null 2>&1 || return 1
    say "  Building from source with $(go version | awk '{print $3}')"
    curl -fsSL --max-time 60 -o "$TMP/src.tar.gz" "https://github.com/$REPO/archive/refs/heads/main.tar.gz" || return 1
    tar -xzf "$TMP/src.tar.gz" -C "$TMP" || return 1
    local dir
    dir=$(find "$TMP" -maxdepth 1 -type d -name 'portbridge-*' | head -1)
    [ -n "$dir" ] || return 1
    ( cd "$dir" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$TMP/portbridge" . ) || return 1
    return 0
}

step "Fetching PortBridge"
if fetch_release; then
    ok "  Downloaded a prebuilt copy"
elif build_from_source; then
    ok "  Built from source"
else
    die "Could not download or build PortBridge.
This server may not be able to reach GitHub. Options:
  - install Go (apt install golang-go) and run this again, or
  - copy the portbridge binary across by hand to $BIN"
fi

install -m 755 "$TMP/portbridge" "$BIN"
say "  Engine: $("$BIN" version)"

# -------------------------------------------------------------- menu + firewall

step "Installing the menu"

get_script() {
    local name=$1 dest=$2
    if [ -f "$TMP/scripts/$name" ]; then
        install -m 755 "$TMP/scripts/$name" "$dest"
        return 0
    fi
    local dir
    dir=$(find "$TMP" -maxdepth 2 -type f -path "*/scripts/$name" 2>/dev/null | head -1)
    if [ -n "$dir" ]; then
        install -m 755 "$dir" "$dest"
        return 0
    fi
    curl -fsSL --max-time 60 -o "$TMP/$name" "$RAW/scripts/$name" || return 1
    install -m 755 "$TMP/$name" "$dest"
}

get_script portbridge-menu "$MENU" || die "Could not install the menu."
get_script portbridge-firewall "$FIREWALL" || die "Could not install the firewall helper."

if [ -f "$TMP/packaging/portbridge@.service" ]; then
    install -m 644 "$TMP/packaging/portbridge@.service" "$UNIT"
else
    unitsrc=$(find "$TMP" -maxdepth 3 -type f -name 'portbridge@.service' 2>/dev/null | head -1)
    if [ -n "$unitsrc" ]; then
        install -m 644 "$unitsrc" "$UNIT"
    else
        curl -fsSL --max-time 60 -o "$TMP/unit" "$RAW/packaging/portbridge@.service" &&
            install -m 644 "$TMP/unit" "$UNIT" || die "Could not install the service template."
    fi
fi

mkdir -p "$CONF_DIR" /run/portbridge
chmod 700 /etc/portbridge "$CONF_DIR"
systemctl daemon-reload

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

ok "
PortBridge is installed."
say "
Open the menu any time with:  ${B}portbridge-menu${R}
"
say "${DIM}Set up the first server, then use the pairing code it gives you on the second.${R}"
say ""

if [ -t 0 ]; then
    printf '%s' "Open the menu now? ${DIM}[Y/n]${R}: "
    read -r a || true
    case "$a" in [nN]*) exit 0 ;; *) exec "$MENU" ;; esac
fi
