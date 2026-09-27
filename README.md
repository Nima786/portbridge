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

## What the link looks like

Plain TCP carrying already-encrypted traffic looks like a burst of random bytes
matching no known protocol, and that is one of the easiest things to single out.
So when you create a tunnel the menu asks how the link should appear, and carries
your answer in the pairing code so both ends always agree.

| Choice | What anyone watching the link sees |
|---|---|
| **Plain** | Random-looking bytes. Slightly faster, easiest to spot. |
| **Look like a normal website** (recommended) | An ordinary secure website connection, including a real handshake if anyone probes the port. |
| **Through Cloudflare or another CDN** | A normal secure websocket request to your domain, with your foreign server's IP never appearing on the link. |
| **Look like a website, with a CDN standing by** | As the second option, but if your foreign server's address ever stops being reachable the link moves to your domain through the CDN by itself. Direct mode only. |

The middle option needs nothing from you but a name for the link to claim, and
that name does not have to be real or yours. A certificate is generated on the
spot. It is not checked for trust, because the shared password already proves who
is who; the certificate is only there to make the handshake look normal.

Be clear about what that option does and does not do. It stops the link being
picked out for matching no known protocol, and it answers a genuine handshake if
the port is probed. It does not hide where the traffic is going: your foreign
server's address is still plainly visible, and a name claimed on the way to an
address that does not own it is a mismatch anyone comparing the two can see. Nor
does it help once the address itself is blocked. That is what the CDN options are
for.

The two CDN options need a domain **you** control, pointed at your foreign server
with the CDN's proxy turned on. Somebody else's domain behind the same CDN cannot
work: the CDN routes by name, so your traffic would be handed to their server,
which does not have your password and would turn it away.

Two more things the CDN needs, both of which the menu states at setup time:

- Its encryption mode must be **Full**. Flexible sends plain traffic to your
  server, which this refuses. Full (strict) demands a publicly trusted
  certificate, which is unnecessary here because the shared password is what
  proves identity.
- The port the two servers use between themselves must be one the CDN forwards.
  For Cloudflare that is 443, 2053, 2083, 2087, 2096 or 8443 ([their port
  list](https://developers.cloudflare.com/fundamentals/reference/network-ports/)).
  The menu only accepts those once you pick a CDN option.

Only the third option hides your foreign server's address; the fourth keeps the
CDN in reserve and uses the direct address while it works, which is faster.

The fourth option is the answer to the most common way a working tunnel dies:
nothing is wrong with either server, but the foreign one's address stops being
reachable. No tunnel software can fix that from the inside. Reaching the same
server by a different name, through addresses nobody wants to block, can. When
that happens the log says which route it moved to, and it tries the direct one
again every couple of minutes.

With that option the link claims a different name on each route, and the
difference is deliberate. Going through the CDN it has to name your domain,
because that is how a CDN knows whose server to forward to. Going straight to
your server it names something ordinary instead, because your domain's own
records point at the CDN rather than at that address, and a name that does not
match where the traffic is going says more to an onlooker than either fact on its
own.

Either CDN option has one consequence worth knowing: the link can arrive from
the CDN rather than from your other server, so the tunnel port cannot be locked
to a single address and is left open. The menu says so at the time. What protects
it then is the disguise: without the right web address and the right password, a
visitor gets a plain 404.

None of this touches your users' own traffic, which Xray has already encrypted.

The default port for the link is 443, because that is the one port nobody finds
odd. The menu warns you if you pick a port that is a known default for something
else.

## One connection per user, or a few shared

The other question the menu asks when you create a tunnel. It is a real trade,
not an upgrade, so it defaults to the way things have always worked.

**One connection per user** is the default. Every user session gets its own
connection across the border. On a poor route this is the faster choice, because
one user's lost packet never holds anybody else up.

**Shared connections** put everyone on a handful of connections that stay open
for hours. Two things get better: the number of connections between your two
servers stops depending on how busy you are, and a hundred simultaneous users no
longer look like a hundred simultaneous connections to the same address, which is
a pattern no disguise hides. The cost is that a lost packet stalls everyone
riding that connection until it is resent, so on a lossy route a hiccup is felt
by several people at once rather than one.

Four shared connections is the default when you turn it on, which limits how
much of your traffic a single stall can affect.

Keep the default unless you have reason to think the sheer number of connections
is what is getting your tunnel noticed.

## Speed tuning

The menu has a **Speed tuning** option. It switches the server to BBR and widens
the network buffers, which matters on a long route between countries: Linux
assumes lost packets mean congestion and slows down hard, and on an intercontinental
link loss is usually just interference. The default reaction throttles a link that
is actually fine. BBR measures how fast data really arrives instead, and on a bad
path the difference is often several times the throughput.

It applies to the whole server, not only to PortBridge, and everything it changes
lives in one file, so the same menu option removes it cleanly.

Worth running on both servers.

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

With shared connections the middle of that changes a little: there are no spares
to wake, so the user's opening bytes and the announcement of a new session go out
together on a connection that is already up. Steps 4 and 5 are the same, including
the retry, which then moves the user to a different shared connection.

## Security

- Every tunnel has its own random password, held in a root-only file. It is never
  passed on a command line, where other users on the server could read it.
- The password is never sent as-is. Each connection sends a fresh signed token,
  so capturing one is no use later.
- On whichever half accepts the connection, the tunnel port is locked to the
  other server's address automatically. The rule is reapplied on every start, so
  it survives a reboot. The exception is a link that may arrive through a CDN,
  where the address it arrives from is the CDN's; the port is then left open and
  the menu tells you.
- The port your users connect to is deliberately left open.
- Traffic is passed through untouched. What PortBridge carries is normally
  already encrypted end to end, so the website disguise is camouflage rather
  than a second layer of protection, and is described that way on purpose.

## Requirements

- Linux with systemd, 64-bit Intel or ARM
- `iptables` for the automatic port locking (optional, but recommended)
- Root

## Files it owns

```
/usr/local/bin/portbridge              the engine
/usr/local/bin/portbridge-menu         the menu
/usr/local/bin/portbridge-firewall     port locking helper
/usr/local/bin/portbridge-tune         speed tuning helper
/etc/systemd/system/portbridge@.service one template for all tunnels
/etc/portbridge/tunnels/<name>.conf    one tunnel's settings
/etc/portbridge/tunnels/<name>.secret  one tunnel's password
/etc/portbridge/tunnels/<name>.crt/.key the disguise certificate, if used
/etc/sysctl.d/99-portbridge-tuning.conf the speed tuning, if applied
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

- No UDP. TCP services only.
- No automatic switching between direct and reverse. A blocked address is handled
  by the CDN backup route above; a broken return path is not, and needs the mode
  changed by hand.

## Licence

MIT. See [LICENSE](LICENSE).
