# PortBridge

Links a port on one server to a service on another. Two servers, one shared
password, a menu to set it up.

It is built for the case where the server your users can reach is not the server
running the thing they want to reach, and the link between the two is unreliable
or restricted in one direction.

## Install

On **both** servers:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Nima786/portbridge/main/install.sh)
```

Set up the first server, and it gives you a pairing code. Paste that into the
menu on the second server and the two halves are connected.

Open the menu again any time:

```bash
portbridge-menu
```

## The two jobs

Every tunnel has two halves, and the job of each never changes:

| Half | What it does |
|---|---|
| **Doorway** | Faces your users. Listens on the port they point their apps at. |
| **Service side** | Sits next to the thing you are publishing, and connects to it only when a real user arrives. |

## The two modes

The mode changes only **which half opens the connection between the servers**.
Everything else behaves identically.

**Direct** — the doorway reaches out to the service side.

```
users ──▶ doorway ══════▶ service side ──▶ your service
                 opens the link
```

Use this by default. It needs the doorway to be allowed to make outbound
connections to the other server's address.

**Reverse** — the service side reaches in to the doorway instead.

```
users ──▶ doorway ◀══════ service side ──▶ your service
                 opens the link
```

Use this when the doorway cannot reach the service side, but the service side can
still reach the doorway. In this mode the service side needs **no open ports at
all**, which is both safer and often the only thing that works.

You can run direct and reverse tunnels side by side on the same pair of servers
for different services. Each tunnel is its own service with its own settings and
its own password, so they cannot interfere. The only rule is that two tunnels
cannot share a port, and the menu checks that for you.

## How a connection is actually made

This is the part that makes it quick and keeps it honest.

1. Whichever half opens the link proves who it is straight away, with a signed
   token that is only valid for a couple of minutes and cannot be replayed.
2. The link then sits there doing nothing, ready and waiting. A handful of these
   spares are kept open at all times, so a user never waits for a new connection
   to be built across a slow route.
3. When a user arrives, the doorway wakes one spare and sends the user's opening
   bytes with it.
4. Only now does the service side touch your service. It connects, then confirms
   back that it got through.
5. If that confirmation never comes, the doorway quietly throws the connection
   away and replays the user's opening bytes down a fresh one. The user sees
   nothing.

Step 4 matters more than it sounds. A spare that had already connected to your
service would show up in its logs as a connection that never says anything, and
your service would eventually hang up on it. Waiting until a real user exists
avoids that entirely.

## Security

- Every tunnel has its own random password, held in a root-only file. It is never
  passed on a command line, where other users on the server could read it.
- The password is never sent as-is. Each connection sends a fresh signed token,
  so capturing one is no use later.
- On whichever half accepts the connection, the tunnel port is locked to the
  other server's address automatically. The rule is reapplied on every start, so
  it survives a reboot.
- The port your users connect to is deliberately left open.
- Traffic is passed through untouched. PortBridge does not add its own
  encryption, because what it carries is normally already encrypted end to end.
  If you need the link itself disguised, this is not the right tool.

## Requirements

- Linux with systemd, 64-bit Intel or ARM
- `iptables` for the automatic port locking (optional, but recommended)
- Root

## Files it owns

```
/usr/local/bin/portbridge              the engine
/usr/local/bin/portbridge-menu         the menu
/usr/local/bin/portbridge-firewall     port locking helper
/etc/systemd/system/portbridge@.service one template for all tunnels
/etc/portbridge/tunnels/<name>.conf    one tunnel's settings
/etc/portbridge/tunnels/<name>.secret  one tunnel's password
/run/portbridge/<name>.json            live status
```

A tunnel called `home` runs as the service `portbridge@home`, so all the usual
commands work:

```bash
systemctl status portbridge@home
journalctl -u portbridge@home -f
```

## Reverse mode depends on the network, not just on this tool

Reverse mode needs the doorway to be able to send data *back* out along a
connection that was opened from outside. That sounds automatic, and usually is,
but it is not guaranteed.

On networks where connections are rewritten on the way in, which is common on
restricted or heavily filtered links, the connection is accepted and data flows
inwards perfectly well, while data going back out is quietly dropped. Nothing
reports an error. The symptom is a connection that hangs instead of failing.

Two signs, checked on the doorway server, that this is what is happening:

```bash
# unsent bytes stuck on a tunnel connection that never clear
ss -nti state established '( sport = :<tunnel-port> )' | grep -B1 retrans
```

If you see the same small amount of unsent data with a growing retransmit count,
while the same connection shows plenty of bytes received, then the path only
works one way and no tunnel software can fix it. Use direct mode instead.

## When something is wrong

Use **Check a tunnel for problems** in the menu. It confirms the service is
running, that the other server is reachable, that spares are ready, and it calls
out the two mistakes that account for most failures: a password that does not
match on both sides, and server clocks that disagree.

## Uninstall

The menu has an option that stops every tunnel, removes the firewall rules it
added, and deletes everything it installed.

## Not included

- No multiplexing. Each user connection uses its own connection across the link.
- No disguise. The link is plain TCP and looks like plain TCP.
- No UDP. TCP services only.

## Licence

MIT. See [LICENSE](LICENSE).
