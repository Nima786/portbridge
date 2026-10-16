# Letting your service see each user's real address

Without this, everything reaches your service from the tunnel on its own server,
so every user looks like the same one. Its logs, per-user IP limits and login
protection all see one address. With it on, PortBridge tells the service each
user's real address, in the standard PROXY protocol header that Xray, nginx,
HAProxy, LiteSpeed and most other servers already read.

It is off unless you turn it on, and creating a tunnel never asks about it. To
turn it on:

1. **Set the service up first**, on the foreign server, to expect the header.
   Once PortBridge sends it, a service that is not expecting it refuses every
   connection through the tunnel.
   - Xray / 3x-ui: turn on Proxy Protocol on that inbound.
   - LiteSpeed: Server, Tuning, PROXY Protocol: `127.0.0.1, ::1`. It still
     accepts ordinary connections as well, so nothing else on the server changes.
   - nginx: add `proxy_protocol` to that `listen` line.
2. **On the Iran server**, choose Edit a tunnel, then Users' real address. The
   foreign server is changed first, through its agent or with a code to paste,
   and if it refuses (an older PortBridge does), nothing changes on either.

The address comes from the connection the user really made to the Iran server,
never from anything the user sent, so nobody can claim someone else's. It crosses
inside the tunnel, after the other server has proved it holds the password. It
works with every kind of link, in both directions, shared connections or not, and
with several services on one tunnel.

The menu turns on version 1 of the header, a line of text every server that
supports the protocol reads. For a service that wants the binary version 2, set
`proxy_protocol = v2` in the tunnel's settings on the Iran server and push it
across with Edit a tunnel (or set it on both servers).

If only one of the two servers has it on, the tunnel keeps working: with only the
foreign server on, the service is told the address is unknown and uses the
connection's own; with only the Iran server on, the service is told nothing. The
foreign server's log says which one to change, and so does Check a tunnel for
problems there. The pairing code carries the setting as version 10, used only
when it is on.

[Back to the README](../README.md)
