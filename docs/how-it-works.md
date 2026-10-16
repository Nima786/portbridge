# How it works

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
- **Active Probing Cover Splicing**: For disguised links with `real_site` enabled, unauthorized probes and censors scanning the tunnel port are transparently proxied to the real cover site (e.g. Bing), obtaining Microsoft's authentic certificate and HTTP responses while keeping PortBridge's server completely invisible.
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

## Files it owns

```
/usr/local/bin/portbridge              the engine
/usr/local/bin/portbridge-menu         the menu
/usr/local/bin/portbridge-firewall     port locking and GRE link helper
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

## Nothing is left in the firewall

Every firewall rule PortBridge adds carries a comment naming its tunnel
(`portbridge:<name>`), and every GRE link a comment naming the link
(`portbridge-gre:<link>`). Deleting a tunnel removes them, on both servers. As a
safety net under that, **sweep** (`portbridge-firewall sweep`) removes any such rule,
and any GRE link, whose tunnel no longer has a settings file. It runs by itself
after every delete (from the menu, from the other server, or through the agent),
after a setup that failed, whenever any tunnel starts, and in full when
PortBridge is uninstalled. It can also be run from the menu (Firewall, then
**Remove leftovers**). It never touches a rule that is not one of those: not
yours, not one that merely looks similar. If the settings directory is missing it
does nothing, since it could not tell what is still wanted.

Earlier versions could leave rules behind on servers that list their rules with
the comment in quotes (nftables does), because the clean-up did not recognise
that form. Those are removed the first time a tunnel starts or is deleted after
updating, or at once with the Firewall menu's last option. Rules from before
rules were tagged cannot be told apart from someone else's and are never touched.

[Back to the README](../README.md)
