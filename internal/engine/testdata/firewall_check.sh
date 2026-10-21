#!/usr/bin/env bash
# Throwaway check of the firewall helper changes, with fake ip/iptables/modprobe.
set -u
FW="$1"
T=$(mktemp -d)
BIN="$T/bin"; CONF="$T/conf"; S="$T/state"
mkdir -p "$BIN" "$CONF" "$S"
export FAKE_STATE="$S" PORTBRIDGE_CONF_DIR="$CONF" PATH="$BIN:$PATH"

cat > "$BIN/ip" <<'EOF'
#!/usr/bin/env bash
# ip -o link show [type KIND]
if [ "$1" = -o ] && [ "$2" = link ]; then
  kind=""
  [ "${4-}" = type ] && kind=$5
  while read -r k n; do
    [ -z "$kind" ] || [ "$k" = "$kind" ] || continue
    echo "9: $n@NONE: <NOARP> mtu 1480"
  done < "$FAKE_STATE/links"
  exit 0
fi
exit 0
EOF
cat > "$BIN/modprobe" <<'EOF'
#!/usr/bin/env bash
echo "modprobe $*" >> "$FAKE_STATE/modprobe.log"
EOF
cat > "$BIN/iptables" <<'EOF'
#!/usr/bin/env bash
R="$FAKE_STATE/rules"; [ "$(basename "$0")" = ip6tables ] && R="$FAKE_STATE/rules6"; touch "$R"
if [ "$1" = "-w" ]; then shift 2; echo "waited" >> "$FAKE_STATE/waited"; fi
cmd=$1; shift
chain=${1-}; shift || true
quote() { sed -E 's/--comment ([^ ]+)/--comment "\1"/'; }
case "$cmd" in
  -S) grep -E "^-A $chain " "$R" || true ;;
  -I)
    [ "$1" = 1 ] && shift
    if [ -n "${FAKE_FAIL_ACCEPT:-}" ] && [[ "$*" == *"-s $FAKE_FAIL_ACCEPT"* ]] && [[ "$*" == *"-j ACCEPT"* ]]; then exit 1; fi
    echo "-A $chain $*" | quote >> "$R" ;;
  -C|-D)
    want=$(echo "-A $chain $*" | quote)
    grep -qxF -- "$want" "$R" || exit 1
    if [ "$cmd" = -D ]; then grep -vxF -- "$want" "$R" > "$R.new"; mv "$R.new" "$R"; fi ;;
esac
exit 0
EOF
cp "$BIN/iptables" "$BIN/ip6tables"
chmod +x "$BIN"/*

fail=0
check() { if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }

conf() {
  printf 'name = t1\nmode = direct\nrole = origin\ntunnel_addr = 0.0.0.0:443\ninbound_addr = 127.0.0.1:80\npeer_ip = 1.2.3.4\nfirewall = %s\ntransport = plain\n' "$1" > "$CONF/t1.conf"
}
seed() {
  cat > "$S/rules" <<'EOF'
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 1.2.3.4/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j DROP
EOF
  : > "$S/rules6"
}

echo "== module unloading"
conf off; seed
printf 'sit sit0\ngre gre0\ngretap gretap0\n' > "$S/links"; : > "$S/modprobe.log"
bash "$FW" apply t1 >/dev/null 2>&1
check "only placeholder links: drivers unloaded" "grep -q 'modprobe -r sit' '$S/modprobe.log' && grep -q 'modprobe -r ip_gre' '$S/modprobe.log'"
printf 'sit sit0\nsit he-ipv6\ngre gre0\n' > "$S/links"; : > "$S/modprobe.log"
bash "$FW" apply t1 >/dev/null 2>&1
check "owner's own 6in4 link: sit driver kept" "! grep -q 'modprobe -r sit' '$S/modprobe.log'"
check "  ...and gre driver still unloaded" "grep -q 'modprobe -r ip_gre' '$S/modprobe.log'"
printf 'sit sit0\ngre gre0\ngre mygre\n' > "$S/links"; : > "$S/modprobe.log"
bash "$FW" apply t1 >/dev/null 2>&1
check "owner's own GRE link: gre driver kept" "! grep -q 'modprobe -r ip_gre' '$S/modprobe.log'"

echo "== firewall off: owner's rules on the port left alone"
conf off; seed
bash "$FW" apply t1 >/dev/null 2>&1
check "all 5 seeded rules still there" "[ \$(grep -c -- '--dport 443' '$S/rules') -eq 5 ]"

echo "== firewall on: only old PortBridge-shaped rules removed"
conf on; seed
bash "$FW" apply t1 >/dev/null 2>&1
check "owner's allow-everyone kept" "grep -qxF -- '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT' '$S/rules'"
check "owner's allow from 9.9.9.9 kept" "grep -qxF -- '-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 443 -j ACCEPT' '$S/rules'"
check "old untagged peer allow removed" "! grep -qxF -- '-A INPUT -s 1.2.3.4/32 -p tcp -m tcp --dport 443 -j ACCEPT' '$S/rules'"
check "old untagged localhost allow removed" "! grep -qxF -- '-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 443 -j ACCEPT' '$S/rules'"
check "old untagged drop removed" "! grep -qxF -- '-A INPUT -p tcp -m tcp --dport 443 -j DROP' '$S/rules'"
check "new tagged rules added (drop + 2 allows)" "[ \$(grep -c 'portbridge:t1' '$S/rules') -eq 3 ]"

echo "== reapplying does not duplicate"
bash "$FW" apply t1 >/dev/null 2>&1
check "still exactly 3 tagged rules" "[ \$(grep -c 'portbridge:t1' '$S/rules') -eq 3 ]"

echo "== turning it off removes ours, keeps owner's"
conf off
bash "$FW" apply t1 >/dev/null 2>&1
check "no tagged rules left" "[ \$(grep -c 'portbridge:t1' '$S/rules') -eq 0 ]"
check "owner's allow-everyone still there" "grep -qxF -- '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT' '$S/rules'"

echo "== iptables is asked to wait for its lock"
check "the -w wrapper was used" "[ -s '$S/waited' ]"

echo "== a port SSH answers on is never locked"
conf on; seed
cat > "$BIN/ss" <<'EOF'
#!/usr/bin/env bash
echo 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
EOF
chmod +x "$BIN/ss"
bash "$FW" apply t1 2>&1 | grep -q "SSH port" && echo "PASS: said so" || { echo "FAIL: did not say it left SSH alone"; fail=1; }
check "no tagged rules were added" "[ \$(grep -c 'portbridge:t1' '$S/rules') -eq 0 ]"
rm -f "$BIN/ss"

echo "== a failed allow does not leave the other server shut out"
conf on; seed
FAKE_FAIL_ACCEPT=1.2.3.4 bash "$FW" apply t1 >/dev/null 2>&1
check "no tagged rules left behind (port left open)" "[ \$(grep -c 'portbridge:t1' '$S/rules') -eq 0 ]"
check "no drop on the port remains from us" "! grep -q 'portbridge:t1.*DROP' '$S/rules'"

echo "== normal apply still locks"
conf on; seed
bash "$FW" apply t1 >/dev/null 2>&1
check "peer allowed" "grep -q -- '-s 1.2.3.4/32.*portbridge:t1.*ACCEPT\|-s 1.2.3.4 .*portbridge:t1.*ACCEPT' '$S/rules'"
check "drop in place" "grep -q 'portbridge:t1.*DROP' '$S/rules'"
check "ipv6 drop in place" "grep -q 'portbridge:t1.*DROP' '$S/rules6'"

rm -rf "$T"
exit $fail
