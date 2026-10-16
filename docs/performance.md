# Speed and busy days

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

[Back to the README](../README.md)
