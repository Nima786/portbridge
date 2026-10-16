# Management agent

PortBridge includes a lightweight, secure management daemon (`portbridge-agent.service`) that enables automated tunnel deployment and teardown:

- **Multi-Server Management from One Iran Server**: Manage multiple Foreign servers (e.g. Germany, Finland, Netherlands) simultaneously from a single Iran server. Each foreign server is saved with a custom nickname/alias (`germany`, `finland`, etc.).
- **Zero-Copy Deployment**: When creating a tunnel on your Iran server, PortBridge automatically matches or prompts for the foreign server, sending the pairing parameters to the foreign agent over HTTPS. The foreign half is immediately configured, validated, and started via systemd without needing to manually copy/paste codes.
- **Dedicated Bearer Auth**: Authentication uses a strong 192-bit cryptographic bearer token (`pba_...`). It **never** requires, asks for, or stores SSH keys or Linux passwords.
- **Flexible Cloudflare-Compatible Ports**: The agent daemon and linking flow allow selecting any custom port freely (e.g. `2083`, `2087`, `2053`, `8443`, `2096`, `443`, etc.). If a port is occupied by another service (such as panels like x-ui), PortBridge detects it in advance and suggests free ports. Because these ports are supported by Cloudflare, the management agent can operate directly or behind Cloudflare CDN proxy even if Iranian ISPs or foreign cloud firewalls block direct IP access!
- **Automatic Remote Teardown**: When you delete a tunnel on your Iran server, PortBridge automatically wipes the corresponding tunnel config, secrets, certificates, and firewall rules on the specific foreign server via the tunnel socket or the agent API.

Setup takes under 30 seconds:
1. On your **Foreign server**: Choose **12) Management Agent** -> **5) Enable & start Agent daemon**. Choose any port you like (e.g. `2083`, `2087`, etc.). It prints your Link String (e.g. `pb-agent://<token>@<ip>:<port>?fp=<fingerprint>`). The fingerprint identifies the agent's certificate: the Iran server pins it, so nobody between the two servers can stand in for the agent and collect its token. If you type the address and token by hand instead, the Iran server shows the fingerprint it sees and asks you to compare it with the one on the foreign server.
2. On your **Iran server**: Choose **12) Management Agent** -> **2) Link a new Foreign server**, paste that string (or enter host, port, token), and give it an alias (e.g. `germany`). Repeat for any additional foreign servers!
3. Every tunnel you create or delete from then on is automated end-to-end!

[Back to the README](../README.md)
