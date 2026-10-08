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

> **💡 Zero-Copy Automation**: If you enable the **Management Agent** on your foreign server (menu option 11), your Iran server can automatically provision and start tunnels on the foreign server over HTTPS — completely eliminating manual copy-pasting of pairing codes!

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

| Menu Option | Applicable Modes | What anyone watching the link sees |
|---|---|---|
| **Option 1: Plain** | Direct & Reverse | Random-looking bytes. Slightly faster, easiest to spot. |
| **Option 2: Look like a normal website** (recommended) | Direct & Reverse | An ordinary secure website connection, including a real handshake if anyone probes the port. |
| **Option 3: Through Cloudflare or another CDN** | Direct & Reverse | A normal secure websocket request to your domain, with your foreign server's IP never appearing on the link. |
| **Option 4: Look like a website, with a CDN standing by** | Direct only | As the second option, but if your foreign server's address ever stops being reachable the link moves to your domain through the CDN by itself. |
| **Option 5: HTTP/2 or gRPC stream** | Direct & Reverse | Wraps the link in HTTP/2 streaming frames over TLS, appearing as active HTTP/2 or gRPC traffic to defeat DPI deep-packet inspection and support Cloudflare gRPC mode. |
| **Option 6: Loss-resistant KCP over UDP (FEC)** | Direct & Reverse | Fast UDP-based transport powered by KCP with Reed-Solomon Forward Error Correction (10 data, 3 parity shards) and AES encryption. Survives up to 30% packet loss and active TCP RST packet drops on unstable routes. |

*(Note: In Reverse mode, Option 4 (CDN standby) is direct-only, so the reverse menu displays the choices seamlessly as 1 to 5).*

A single tunnel can forward multiple ports / services at once: enter comma-separated ports (e.g. `443, 8443, 2083`) when creating or editing the tunnel.

The **KCP / UDP option** replaces the underlying TCP transport between the two servers with turbo-paced KCP packets over UDP. Reed-Solomon FEC (10 data + 3 parity shards) reconstructs dropped packets immediately without waiting for a retransmission round-trip, making it ideal for international links suffering heavy packet loss or middlebox TCP reset injection.

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
- The CDN must forward the port the two servers use between themselves.
  Cloudflare forwards only 443, 2053, 2083, 2087, 2096 and 8443 ([their port
  list](https://developers.cloudflare.com/fundamentals/reference/network-ports/)).
  Other providers, ArvanCloud for one, forward more, so the menu does not refuse
  any port: it points out that a port is not one Cloudflare forwards and carries
  on, and it is up to you to make sure your provider forwards it.

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
not an upgrade. The menu suggests one connection per user for a plain link or a
website disguise, and shared connections for the websocket, gRPC and KCP options,
where opening a fresh disguised connection for every user is the costly part.
Option 1 is always "one connection per user" and option 2 is always "shared".

Both servers must agree. The menu makes sure of that by putting the choice in the
code, and if someone edits a settings file by hand and they disagree, both
servers now say so in the log, by name, within moments, instead of leaving users
to wait.

**One connection per user** gives every user session its own connection across
the border. On a poor route this is the faster choice, because one user's lost
packet never holds anybody else up.

**Shared connections** put everyone on a handful of connections that stay open
for hours. Two things get better: the number of connections between your two
servers stops depending on how busy you are, and a hundred simultaneous users no
longer look like a hundred simultaneous connections to the same address, which is
a pattern no disguise hides. The cost is that a lost packet stalls everyone
riding that connection until it is resent, so on a lossy route a hiccup is felt
by several people at once rather than one.

Four shared connections is the default when you turn it on, which limits how
much of your traffic a single stall can affect.

Keep the suggestion unless you have reason to think the sheer number of
connections is what is getting your tunnel noticed.

One measured exception is worth knowing. If you are using a disguise **and** your
users make many short-lived connections, shared connections do about a quarter of
the work per user. A connection that carries one user and is then thrown away has
to set the disguise up again for the next one, and that setup is the most
expensive thing either server does. Sharing pays it once and then stops paying.
For large steady transfers it is the other way round, and one connection per user
is cheaper. On a plain link with no disguise the two are about even.

## Making a plain link open like web traffic

The plain option starts with random-looking bytes, and some networks refuse
anything that opens like nothing they recognise while letting ordinary web traffic
through. When you choose plain, the menu asks whether to make it **open like web
traffic**, and for a site name to use (any believable name, default
`www.bing.com`; it does not have to be yours). The side that connects sends a
short, browser-like web request naming that site, the other side answers with a
normal-looking reply, and the tunnel carries on exactly as before.

Measured on a real route into Iran, from outside, with a 6 MB download through the
tunnel: the plain link stalled after a few kilobytes and the same tunnel with this
turned on finished the download in about five seconds, both times it was tried.

What it is and is not: it is not encryption, and after the first lines it is not
real HTTP, so a filter that follows the whole conversation would see through it.
It helps against filters that judge a connection by how it starts. Both servers
must have it on or off together. The pairing code carries it (as version 7, used
only when the header is on, so older servers keep working with every tunnel that
does not use it), and if the two disagree each side says so in the log. In the
settings file it is `http_header = on` and `http_host = <name>`, for the plain
link only.

## Changing a tunnel's ports

Menu option 5 (Edit a tunnel), then **Change ports**, on the Iran server. Three
kinds of port can be changed, together or one at a time:

- the ports your users connect to (on the Iran server),
- the service ports they lead to on the foreign server, in the same order, and
- the private link port the two servers use between themselves.

The foreign server is changed to match. When it is linked by the agent this is
automatic: the foreign server checks its ports **before changing anything**, and
if a port is busy, or belongs to another tunnel's link, or the service port equals
the link port, it refuses with every problem listed. Nothing is changed on either
server, and you are asked to choose other ports. If the new settings will not run,
the old ones are put back and started again. When the foreign server is not
linked, the menu shows a code to paste there with "Join a tunnel", which offers to
change the existing tunnel's ports (it has to be the same tunnel: the password in
the code must match).

The same checks run when a tunnel is first set up on the foreign server, whether
by the agent or by pasting a code. A service port that nothing is answering on yet
is reported as a note, not an error, since the service may simply not be started.

## When connections open but nothing gets through

The hardest failure to spot is not a tunnel that is down. It is a route that lets
a connection open, carries its first few packets, and then quietly stops. Every
connection looks healthy. The menu used to show "ready" and users waited for
replies that never came. Measured on a real route, every connection was cut after
about six packets, in both directions, whatever the port or protocol. Nothing in
either server is wrong when that happens, and no setting on either server can fix
it. What fixes it is reaching the other server by a different route.

So the tunnel no longer takes "ready connections" as proof. Three things now
happen:

- **It measures.** The side that dials moves a small test transfer, larger than
  the few packets such a route lets through, over the same route real users
  take. It is skipped while real users are getting through, so a busy tunnel
  spends nothing on it. The result is in the status: `data flows`, or a plain
  statement that connections open but nothing gets through.
- **It moves.** With a backup route configured (menu option 4, the website with a
  CDN in reserve), two failed tests in a row set the route aside and traffic goes
  to the backup. The preferred route is tried again regularly and used again only
  after a test over it succeeds.
- **It says so.** Without a backup it still reports the problem honestly, once,
  in the log, and in the menu's check: this is the route being filtered, and the
  options are another address or server, or a CDN.

Turn the test off with `path_probe = off` in a tunnel's settings if you ever need
to. The idle cost is a few tens of megabytes a day at most.

Spare connections are checked the same way for every link type, including plain,
so a spare that has died silently is dropped before a user lands on it.

For a tunnel through a CDN, the browser-style handshake, the split first packet
and the list of clean addresses now follow the route, not the tunnel: a backup
route through a CDN gets them even when the main route goes straight to the
server. The pairing code carries them too, so the foreign server does not forget
them.

## Many users at once

The number of ready connections is the setting that matters here, and it is worth
understanding before a busy day rather than during one.

A user who arrives when a connection is already waiting is served immediately.
Once they are used up, the next users wait while fresh ones are opened across the
border, which costs a round trip or two. The default of 25 is plenty for a handful
of people and not enough for a crowd arriving together.

Measured on a real pair of servers about 90 ms apart, 100 users arriving at the
same instant: with 25 ready, the slowest users waited about three times as long to
be connected as the quickest. With the number raised above the user count, that
gap disappeared.

Two things to know when raising it:

- **Both servers must be changed.** They each hold the same setting and the lower
  of the two decides. Changing one side only appears to work and does nothing.
  The menu says so when you edit it.
- **More ready connections mean more connections held open between your servers**,
  which is a slightly larger pattern for anyone watching. If that worries you more
  than the wait does, the shared-connections option is the other way to handle a
  crowd.

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

## In-tunnel speed test

PortBridge includes a built-in benchmarking tool to test live latency, jitter, download throughput, and upload throughput directly through an active tunnel without requiring external speedtest scripts or third-party servers:

```bash
# Using the interactive menu (Option 10)
portbridge-menu speedtest <tunnel-name>

# Or directly via the CLI
portbridge speedtest <tunnel-name> [size_in_mb]

# Example: Run a 20 MB throughput test on tunnel "kcp1"
portbridge speedtest kcp1 20
```

The speedtest operates across three lockstep phases through the active tunnel:
1. **RTT & Jitter**: Computes real-time round-trip latency and network jitter.
2. **Download Test**: Streams high-entropy pseudorandom payload data from the foreign server to the edge server.
3. **Upload Test**: Streams verified test payload data from the edge server back to the foreign server.

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
- **Zero-Magic Protocol v2 Framing**: Cross-border connection framing is disguised with an ephemeral HMAC mask derived from the shared secret. Handshake frames contain no fixed magic bytes or protocol signatures, making them indistinguishable from random encrypted entropy to DPI sniffers.
- **Randomized Handshake Padding**: Handshake frames append 16 to 64 bytes of cryptographically randomized padding to eliminate static packet size fingerprints.
- **Anti-Replay Sliding Window**: A timestamp window combined with a bitmask nonces cache ensures captured handshake packets cannot be replayed.
- **0-RTT Early Data**: When using WebSocket / CDN transports, authentication is carried directly in the HTTP Upgrade handshake (`Sec-WebSocket-Protocol`), establishing authenticated connections with zero round-trip delay.
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
/etc/systemd/system/portbridge-agent.service management agent daemon service
/etc/portbridge/agent.conf             foreign management agent configuration & token
/etc/portbridge/agent-client.conf      Iran server connection info to foreign agent (default)
/etc/portbridge/agents/<alias>.conf    saved foreign server profiles (for multi-server setups)
/etc/portbridge/tunnels/<name>.conf    one tunnel's settings
/etc/portbridge/tunnels/<name>.secret  one tunnel's password
/etc/portbridge/tunnels/<name>.crt/.key the disguise certificate, if used
/etc/sysctl.d/99-portbridge-tuning.conf the speed tuning, if applied
/run/portbridge/<name>.json            live status
/run/portbridge/<name>.sock            local IPC & remote teardown control
```

A tunnel called `home` runs as the service `portbridge@home`, so all the usual
commands work:

```bash
systemctl status portbridge@home
journalctl -u portbridge@home -f
```

### Management Agent (Multi-Server Automation)

PortBridge includes a lightweight, secure management daemon (`portbridge-agent.service`) that enables automated tunnel deployment and teardown:

- **Multi-Server Management from One Iran Server**: Manage multiple Foreign servers (e.g. Germany, Finland, Netherlands) simultaneously from a single Iran server. Each foreign server is saved with a custom nickname/alias (`germany`, `finland`, etc.).
- **Zero-Copy Deployment**: When creating a tunnel on your Iran server, PortBridge automatically matches or prompts for the foreign server, sending the pairing parameters to the foreign agent over HTTPS. The foreign half is immediately configured, validated, and started via systemd without needing to manually copy/paste codes.
- **Dedicated Bearer Auth**: Authentication uses a strong 192-bit cryptographic bearer token (`pba_...`). It **never** requires, asks for, or stores SSH keys or Linux passwords.
- **Flexible Cloudflare-Compatible Ports**: The agent daemon and linking flow allow selecting any custom port freely (e.g. `2083`, `2087`, `2053`, `8443`, `2096`, `443`, etc.). If a port is occupied by another service (such as panels like x-ui), PortBridge detects it in advance and suggests free ports. Because these ports are supported by Cloudflare, the management agent can operate directly or behind Cloudflare CDN proxy even if Iranian ISPs or foreign cloud firewalls block direct IP access!
- **Automatic Remote Teardown**: When you delete a tunnel on your Iran server, PortBridge automatically wipes the corresponding tunnel config, secrets, certificates, and firewall rules on the specific foreign server via the tunnel socket or the agent API.

Setup takes under 30 seconds:
1. On your **Foreign server**: Choose **11) Management Agent** -> **5) Enable & start Agent daemon**. Choose any port you like (e.g. `2083`, `2087`, etc.). It prints your Link String (e.g. `pb-agent://<token>@<ip>:<port>?fp=<fingerprint>`). The fingerprint identifies the agent's certificate: the Iran server pins it, so nobody between the two servers can stand in for the agent and collect its token. If you type the address and token by hand instead, the Iran server shows the fingerprint it sees and asks you to compare it with the one on the foreign server.
2. On your **Iran server**: Choose **11) Management Agent** -> **2) Link a new Foreign server**, paste that string (or enter host, port, token), and give it an alias (e.g. `germany`). Repeat for any additional foreign servers!
3. Every tunnel you create or delete from then on is automated end-to-end!

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

- Forwarding arbitrary raw client UDP ports (while PortBridge provides a loss-resistant UDP-based KCP transport with FEC for the cross-border link, client services forwarded through the tunnel are TCP).
- No automatic switching between direct and reverse. A blocked address is handled
  by the CDN backup route above; a broken return path is not, and needs the mode
  changed by hand.

## Licence

MIT. See [LICENSE](LICENSE).
