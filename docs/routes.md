# Routes between the two servers

## Connecting the two servers over IPv6

Some networks cut ordinary IPv4 connections between countries after a few packets and
leave IPv6 alone. Between a real Iran server and a foreign one where a plain IPv4 tunnel
stalled after 13 KB, the same plain tunnel over IPv6 moved 20 MB down in about 1.3
seconds and 10 MB up in about 1.9, at around 16 MB per second, with the firewall lock
on. Nothing has to be made or set up: it is the same link with IPv6 addresses.

When you create a tunnel, if this server has a public IPv6 address, the menu asks
**"Connect the two servers over IPv6?"**, after you have chosen the foreign server and
before any port. It finds the foreign server's IPv6 address through its agent (without
one, you type it), shows both, and pings it before going on. On a server with no public
IPv6 address (one that shows only an address starting fe80, which is for its own
network only) it says so in one line and uses IPv4.

- Your users still connect to the Iran server the way they do now, over IPv4. Only the
  link between your two servers uses IPv6.
- It is offered for the plain link (with or without the web header) and for the
  disguised links that connect straight to the foreign server: the website (TLS),
  HTTP/2 and gRPC links, which kept the disguise and ran at full speed over IPv6 in a
  trial between a real Iran server and a foreign one, and the KCP link, which held up
  best on a route that was losing packets. It is not offered with a CDN (which reaches
  the foreign server by name), with GRE (IPv4 only), or with the web-socket link, which
  has not been tried over IPv6. When it is not offered the menu says why in one line
  instead of skipping the question.
- If ordinary IPv4 does not work between the two servers at all (some Iran servers can
  reach only Iranian addresses over IPv4), give the foreign server's IPv6 address where
  it asks for the foreign server's IP. The menu then asks nothing more about the
  address, and sets up both ends for IPv6 together. If this server has no public IPv6
  address, or the link type cannot use it, it stops and says so instead of making a
  tunnel that cannot connect.
- Linking the foreign server's agent works over IPv6 as well. The agent menu on the
  foreign server shows a second link string with its IPv6 address in square brackets,
  `pb-agent://<token>@[2001:db8::1]:<port>?fp=...`, and if linking over IPv4 fails the
  menu offers to try the IPv6 address.
- The firewall lock works for IPv6 too: the port is open to the other server's IPv6
  address only, and shut over IPv4. The tunnel connects from the address in its
  settings, so a server with several IPv6 addresses always uses the one that is let in.
- Both servers need working IPv6. The foreign server must run this version for the
  menu to find its address; otherwise you type it.
- In the settings file there is nothing new: `peer_ip`, `local_ip` and `tunnel_addr` hold
  IPv6 addresses (`tunnel_addr` in brackets, `[2001:db8::1]:443`). The pairing code is
  unchanged; an IPv6 address in it makes the foreign server listen on IPv6. From the
  command line, `portbridge addresses` lists a server's public addresses, and
  `portbridge join -agent <alias> -addresses` those of the foreign one.

## Carrying a tunnel over a private GRE link

Some networks cut ordinary connections that leave the country after a few packets
(a few kilobytes get through, then nothing), yet let **GRE** through. GRE is IP
protocol 47, not TCP or UDP: a plain wrapper that joins two servers with a private
network between them. When you create a tunnel the menu asks **"Carry it over a
private GRE link?"**. If you say yes, the tunnel talks to the other server's
*private* address on that link, so the only thing that crosses the border between
the two public addresses is GRE.

Measured between a real Iran server and a foreign one, where an ordinary plain
tunnel stalled after a few kilobytes: with GRE, 20 MB came down in about 1.5
seconds and 10 MB went up in about 2, in both direct and reverse mode, at
13 to 18 MB per second, on a plain link with no disguise and no CDN.

What to know before using it:

- It is **not encrypted and not disguised**. Anyone watching can tell it is GRE,
  and a network that blocks GRE blocks it. Use it when a normal tunnel connects but
  no data flows; it is a different way across, not a hiding place.
- **Both servers must hold their own public IPv4 address** on a network card. A
  server behind address translation (a private address on the card, a public one
  added by the host) cannot receive GRE, and the menu says so before changing
  anything. The host must also allow GRE: some low-cost plans and containers
  (OpenVZ, LXC) do not. The menu tests for this first (`portbridge-firewall gre-check`).
- It cannot be combined with a CDN or a disguise. The link inside GRE is plain.
- The private addresses come from `10.99.0.0/16`, worked out from the two public
  addresses alone, so both servers agree without any extra step. All tunnels
  between the same two servers share one link, and it is removed when the last of
  them is deleted. It is remade on every start, so it survives a reboot.
- The other server's IP cannot be edited on a GRE tunnel, because the link is tied
  to that pair of addresses. Delete the tunnel and create it again for a new server.
- In the settings file it is `gre = on`, `gre_local` (this server's public address)
  and `gre_remote` (the other's); `tunnel_addr` and `peer_ip` then hold addresses
  on the link. The pairing code carries it as version 8, used only when GRE is on.
  **Check a tunnel for problems** tests the link and says whether the other end
  answers.

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

[Back to the README](../README.md)
