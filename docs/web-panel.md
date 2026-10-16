# Web panel

The web panel shows every server and every tunnel in one place, in a browser.
Set it up on **one** of your servers; from the panel you add the others.

From the panel you add servers, make and delete tunnels between them, start,
stop and restart them, and update PortBridge on every server with one click.

## Setting it up

On the server that will run the panel:

```
portbridge-menu   ->  Web panel  ->  Set up the web panel
```

It asks for:

- **A username and password** to log in with (at least 10 characters).
- **A port.** It suggests a free one. 2053, 2083, 2087, 2096 and 8443 also work
  if you later put the panel behind Cloudflare.
- **A domain name**, optional. With one, the panel gets a real certificate from
  Let's Encrypt and renews it by itself, so the browser does not warn. Point the
  name (an A record) at the server first. Getting the certificate needs port 80
  free on that server, unless the panel itself is on port 443.
- **Whether this server is a relay (Iran) or a foreign server**, or neither.

At the end it prints the address to open, and the fingerprint of the panel's own
certificate. Without a domain name the browser warns that the connection is not
private, because the panel made its own certificate. Check that the
certificate's SHA-256 fingerprint in the browser matches the one printed, then
continue.

## Adding a server

In the panel, **Add server** asks for the server's address, whether it is a relay
or a foreign server, and how to log in to it over SSH: its root password, a
pasted private key, or a key file.

The panel then logs in once and:

1. installs PortBridge there if it is missing, using its own copy, so the server
   does not need to reach GitHub (common in Iran). If the server has an older
   PortBridge, it is updated only when **update it** is ticked, because its
   tunnels restart for a few seconds;
2. switches on the server's management agent, keeping its token and port if it
   already had one, so an Iran server's link to it keeps working;
3. checks it can reach the agent **without SSH**. If it cannot, it asks the
   server to call the panel instead, which works when the panel cannot reach the
   server but the server can reach the panel.

Only when one of those works is the server saved. The SSH password or key is
used for this one job and is never written anywhere. What the panel keeps is the
agent's own token, encrypted.

Removing a server from the panel only makes the panel forget it. PortBridge and
its tunnels stay on that server and keep working.

## Making a tunnel

**New tunnel** (or drag a relay server's card onto a foreign server's card) asks
the same questions as the menu's "Create a tunnel", as one form: the two servers,
a name, direct or reverse, how the link looks (plain, a normal website, through a
CDN, a website with a CDN standing by, HTTP/2, KCP, or over GRE), IPv6 when both
servers have it, shared connections, the ports, and whether your service is told
your users' real addresses. Only the questions that apply are shown.

**Check these ports on both servers** asks both servers whether the ports are free,
and whether your service is listening on the foreign one, before anything is made.

The panel then makes the Iran half on the relay server and the foreign half on the
foreign server. The tunnel is exactly the one the menu would have made, so the menu
can still show, edit and delete it. If the foreign half cannot be made, the Iran
half is taken away again, so nothing is left half-made, and the reason is shown.

Each tunnel has **Restart**, **Stop** or **Start**, **Show its code** (for pasting on
a foreign server by hand) and **Delete**, which removes it from both servers. If a
server cannot be reached, the panel says what to do on that server by hand.

## Updating

When a newer release is out, or a server has an older PortBridge than the panel,
**Update everything** appears. It updates the panel's own server first, if it is
behind: the panel restarts on the new version, you log in again, and it carries on
with the other servers by itself. Then each other server, one at a time, so only one
server's tunnels restart (for a few seconds) at any moment.

A server downloads the release from GitHub itself and checks it against the
published checksum. A server that cannot reach GitHub, which is common in Iran, is
sent the release by the panel; when the panel's own server cannot reach GitHub
either, a foreign server downloads it for the panel.

A server with a PortBridge from before one-click updates (0.14 and older) has to be
updated once with its SSH login. Its card offers **Update it with its SSH login**;
the login is used for that alone and not kept. From then on it updates with one
click.

Being able to update a server means the panel can install software on it. That is
allowed on the servers you add to the panel (it is the `allow_updates = on` line in
`/etc/portbridge/agent.conf` on each), so keep the panel's password strong. To stop
the panel updating one server, set that line to `off` there.

## The tunnels page

Each tunnel is drawn with both of its ends: where users connect, the relay, the
link between the two servers (and which side opens it), the foreign server, and
the service. Below it: how many users are connected, whether the spare
connections or shared links are ready, whether data really gets through, how long
it has been up, and whether users' real addresses are passed on.

The two ends are matched by a short fingerprint of the tunnel's password, never
the password itself. A tunnel whose other end is on a server not in the panel is
shown with that end missing.

## Security

- The login is protected against guessing: five wrong passwords from one address
  lock it out for 15 minutes.
- Sessions end after two hours unused, and after twelve hours in any case.
  Changing the login logs everyone else out.
- The page only accepts changes from itself, and loads nothing from anywhere else.
- The panel keeps everything in `/etc/portbridge/panel`, readable by root only.

Forgot the password? On the panel's server: **Web panel -> Change the login**.

## Commands

The menu uses these; they can also be run by hand.

```
portbridge panel status                 how the panel is set up
portbridge panel setup [options]        set it up, or change a setting
portbridge panel reset-password -user U the password is read from standard input
journalctl -u portbridge-panel          its log
```
