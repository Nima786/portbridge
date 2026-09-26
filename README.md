# PortBridge

Links a port on one server to a service on another. Two servers, one shared
password, a menu to set it up.

It is built for the case where the server your users can reach is not the server
running the thing they want to reach, and the link between the two is unreliable
or restricted in one direction.

## Install

Run this on **both** machines:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Nima786/portbridge/main/install.sh)
```

Then:

1. On your **Iran server** (the IP in your users' configs), choose **Create a
   tunnel**. It asks everything once and gives you a code at the end.
2. On your **foreign server** (the one with your panel), choose **Join a
   tunnel** and paste that code. It asks nothing else.

That order is the same for direct and reverse.

After that, the menu is one word:

```bash
portbridge-menu
```

Running the install command again is also how you update. It checks for a newer
version and, if there is nothing to do, goes straight to the menu instead of
reinstalling. Add `--force` to reinstall anyway.

## Your two servers

| Server | What it is |
|---|---|
| **Iran server** | The IP in your users' configs. They connect here. |
| **Foreign server** | Runs your panel and Xray inbound. The traffic ends up here. |

That is true whichever mode you choose, so the menu never asks which server it is
on. Choosing **Create** means you are on the Iran server, and **Join** means you
are on the foreign server.

## Direct or reverse

This is the only real decision. It changes **which server starts the connection
between the two**, and nothing else. Your users' configs still point at the Iran
server either way, and they never notice the difference.

**Direct** — the Iran server connects out to the foreign server.

```
users ──▶ Iran server ══════▶ foreign server ──▶ Xray
                      connects out
```

Try this first. It works in most cases.

**Reverse** — the foreign server connects in to the Iran server instead.

```
users ──▶ Iran server ◀══════ foreign server ──▶ Xray
                      connects in
```

Use this if direct stops working, usually because the Iran server can no longer
reach the foreign server's IP. The foreign server then needs no open port for the
tunnel.

People who know Rathole or Backhaul may know the Iran side as the "server" in
reverse mode. PortBridge avoids those words entirely and just says Iran and
foreign.

Reverse is not automatically better. Read the section below before relying on it.

You can run direct and reverse tunnels side by side on the same pair of servers,
for different inbounds. Each tunnel is separate, with its own settings and its own
password, so they cannot interfere. The only rule is that two tunnels cannot share
a port, and the menu checks that for you.

## How a connection is actually made

This is the part that makes it quick and keeps it honest.

1. Whichever half opens the link proves who it is straight away, with a signed
   token that is only valid for a couple of minutes and cannot be replayed.
2. The link then sits there doing nothing, ready and waiting. A handful of these
   spares are kept open at all times, so a user never waits for a new connection
   to be built across a slow route.
3. When a user arrives, the Iran server wakes one spare and sends the user's opening
   bytes with it.
4. Only now does the foreign server touch your inbound. It connects, then confirms
   back that it got through.
5. If that confirmation never comes, the Iran server quietly throws the connection
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

## Reverse mode depends on your network, not just on this tool

Reverse mode needs the Iran server to be able to send data *back* out along a
connection that was opened from outside. That sounds automatic, and usually is,
but it is not guaranteed.

On networks where connections are rewritten on the way in, which is common on
restricted or heavily filtered links, the connection is accepted and data flows
inwards perfectly well, while data going back out is quietly dropped. Nothing
reports an error. The symptom is a connection that hangs instead of failing.

How to recognise it, checked on the Iran server:

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
