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

> **💡 Zero-Copy Automation**: If you enable the **Management Agent** on your foreign server (menu option 12), your Iran server can automatically provision and start tunnels on the foreign server over HTTPS — completely eliminating manual copy-pasting of pairing codes!

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

Reverse is not automatically better. Read [Reverse mode depends on your network](docs/routes.md#reverse-mode-depends-on-your-network-not-just-on-this-tool) before relying on it.

You can run direct and reverse tunnels side by side on the same pair of servers,
for different inbounds. Each tunnel is separate, with its own settings and its own
password, so they cannot interfere. The only rule is that two tunnels cannot share
a port, and the menu checks that for you.

## Documentation

- [What the link looks like](docs/link-types.md): plain, website, CDN, HTTP/2, gRPC and KCP links, the
  real-website defence, and making a plain link open like web traffic.
- [Routes between the two servers](docs/routes.md): IPv6, a private GRE link, what happens when a route
  stops carrying data, and when reverse mode cannot work.
- [Ports](docs/ports.md): which ports are free on both servers, and changing a tunnel's ports.
- [Letting your service see each user's real address](docs/real-address.md).
- [Speed and busy days](docs/performance.md): one connection per user or a few shared, many users at
  once, speed tuning and the built-in speed test.
- [Management agent](docs/management-agent.md): setting up and deleting tunnels from the Iran server alone.
- [Web panel](docs/web-panel.md): every server and tunnel in a browser, and adding servers from it.
- [How it works](docs/how-it-works.md): how a connection is made, security, the files PortBridge owns,
  and how it keeps the firewall clean.

## Requirements

- Linux with systemd, 64-bit Intel or ARM
- `iptables` for the automatic port locking (optional, but recommended)
- Root

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
  by the CDN backup route ([routes](docs/routes.md)); a broken return path is not, and needs the mode
  changed by hand.

## Licence

MIT. See [LICENSE](LICENSE).
