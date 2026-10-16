# Ports

## Which ports are free, on both servers

The link between the servers needs a port that is free on the server that opens
it, and a CDN forwards only some ports. Both are easy to forget, so the menu shows
them side by side: **Show free ports on both servers** (menu option 11). The
same table appears when you pick the link port of a tunnel that goes through a CDN,
while creating it or changing its ports. Only those tunnels are limited in which ports
they can use, so the menu asks what the link looks like (GRE, plain, website, CDN...)
before it asks about any port, and every other kind of tunnel can use any port.

```
PORT   THIS SERVER             FOREIGN SERVER          CDN
443    busy (nginx)            free                    Cloudflare
2053   free                    busy (x-ui)             Cloudflare
2083   free                    free                    Cloudflare   free on both
8080   free                    free                    other CDNs   free on both
```

- **busy** means a program is listening on it, and the table says which.
  **reserved** means nothing is listening yet, but one of that server's own
  tunnels is set to use it, so it would clash the moment that tunnel starts.
- The CDN column says whether Cloudflare forwards the port. The rest are ports other
  providers, such as ArvanCloud, forward; check yours does.
- A port must be free on the server that *opens* it: the foreign server in direct
  mode, the Iran server in reverse. **Free on both** is the safest choice, since it
  keeps working if you switch modes later. The question that follows suggests the
  first port that suits.
- Whatever kind of tunnel it is, the ports you type are checked as you type them, on
  both servers: your users' ports and the link port (when this server opens it) on this
  one, and on the foreign server the link port (when it opens it, which must be free
  there) and the service ports (which should already have your service listening, and
  must not be another tunnel's link). A busy port is refused on the spot, with what is
  using it; a service port nothing listens on yet asks whether to go on. When the
  foreign server cannot be asked, the menu says so once and the foreign server checks
  the ports itself when the tunnel is set up there.
- Whatever kind of tunnel it is, the ports you type are checked as you type them, on
  both servers: your users' ports and the link port (when this server opens it) on this
  one, and on the foreign server the link port (when it opens it, which must be free
  there) and the service ports (which should already have your service listening, and
  must not be another tunnel's link). A busy port is refused on the spot, with what is
  using it; a service port nothing listens on yet asks whether to go on. When the
  foreign server cannot be asked, the menu says so once and the foreign server checks
  the ports itself when the tunnel is set up there.
- The foreign server is asked through its agent (see [the management agent](management-agent.md)),
  so it needs one linked, and the same PortBridge version. Without that, only this
  server is shown and the table says so. From the command line:
  `portbridge ports 443,2053,8443` for this server, and
  `portbridge join -agent <alias> -ports 443,2053,8443` for the foreign one.

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

[Back to the README](../README.md)
