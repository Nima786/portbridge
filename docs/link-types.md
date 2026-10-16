# What the link looks like

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

How much one connection may have in flight matters most on a long route. It used to be
128 packets, which limits a connection to about 2 MB per second when the route has a
delay of 90 ms, however much room there is. It is now 2048. Between a real Iran server
and a foreign one over IPv6, on a route losing about 12% of the packets coming back, an
8 MB download that took 14 seconds took about 3, and on a clean route one that took 5
took under one. Several downloads at once were also two to three times faster. More
repair shards, a shorter tick, earlier resending and smaller packets made no
measurable difference, so those are unchanged. For a server with very little memory,
the setting can be lowered in the tunnel's settings file; none of these has to match on
the two servers, only the shard counts do:

```
kcp_window = 2048             # packets in flight per direction (16 to 32768)
kcp_mtu = 1400                # bytes in one UDP packet (500 to 1500)
kcp_interval = 10             # milliseconds between ticks (5 to 100)
kcp_resend = 2                # resend after this many later packets were acknowledged (0 = off)
kcp_congestion_control = off  # on = slow down when packets are lost
```

The middle option needs nothing from you but a name for the link to claim, and
that name does not have to be real or yours. A certificate is generated on the
spot. It is not checked for trust, because the shared password already proves who
is who; the certificate is only there to make the handshake look normal.

### Active Probing Defense: Show the real website to strangers

When an active probe or censor connects to a disguised port (`tls`, `h2`, `grpc`, or direct `wss`), the default defense is to never answer for itself. With **"Show the real website to strangers"** (`real_site = on`, enabled by default for new website, HTTP/2, gRPC, and WebSocket links):

1. **Foreign-server check**: The listening server reads the opening message (`ClientHello`) without answering.
2. **Client proof**: An authentic PortBridge client embeds a 32-byte cryptographic proof (masked timestamp, random nonce, and HMAC-SHA256 signature derived from the shared secret) inside the TLS ClientHello's `legacy_session_id`, using a realistic Chrome browser fingerprint (`uTLS`).
3. **Transparent Splicing to the Real Site**: Any visitor without the authentic proof—such as censors, security scanners, arbitrary probes, or invalid protocols—is instantly and transparently piped directly to the genuine cover site (e.g. `www.bing.com:443`). Probers negotiate TLS directly with Microsoft or the chosen cover site and receive their authentic certificate, cipher suites, and real pages. PortBridge's server never answers or exposes its own certificate to strangers.
4. **Anti-Replay Protection**: A copied ClientHello from a real client cannot be replayed by a censor to elicit PortBridge's certificate; replayed packets fail the replay guard cache and are forwarded straight to the real cover site.
5. **Reverse Mode Support**: In reverse mode where the Iran server is the listener, the setup menu automatically tests candidates to suggest a cover website that is reachable and unblocked from inside Iran.

Existing tunnels stay unchanged. Pairing codes carry `real_site` (as pairing code version 9), ensuring both servers agree automatically.

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

## Making a plain link open like web traffic

The plain option starts with random-looking bytes, and some networks refuse
anything that opens like nothing they recognise while letting ordinary web traffic
through. When you choose plain, the menu asks whether to make it **open like web
traffic**, and for a site name to use (any believable name, default
`www.bing.com`; it does not have to be yours). The side that connects sends a
realistic browser web request naming that site, the other side answers with a
normal-looking reply, and the tunnel carries on exactly as before.

Requests are dynamically rotated across modern browser profiles (Chrome, Edge,
Firefox, Safari on Windows and macOS), including modern browser headers (`Sec-Ch-Ua`,
`Sec-Fetch-*`, `Accept-*`) and plausible cookies, bringing the initial greeting to a
realistic browser request size (500–800+ bytes) and preventing static byte fingerprinting.
If scanners probe the port with non-HTTP garbage, the server answers with an authentic
nginx `HTTP/1.1 400 Bad Request` page before closing, completely masking the tunnel.
On plain links without web traffic disguise, probes are drained and closed with natural jitter
to eliminate instantaneous timing tells.

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

[Back to the README](../README.md)
