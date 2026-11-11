# Next-Generation Transport Innovations Roadmap

This document tracks the gradual rollout of PortBridge's six next-generation anti-DPI, anti-QoS, and low-latency tunnel transport modes.

---

## Phase 1 (Implemented in `v0.17.57`–`v0.17.58`)

### 1. Dynamic Port-Hopping KCP (`kcp-hop` / `port_hop = on`)
- **Status**: ✅ Implemented (`v0.17.57`)
- **Problem Solved**: ISPs and mobile/fixed-line middleboxes throttle or rate-limit long-lived UDP flows after 30–120 seconds on the same 5-tuple (`srcIP`, `srcPort`, `dstIP`, `dstPort`, `UDP`).
- **Architecture**:
  - Wraps UDP sockets in a session-authenticated `net.PacketConn` (`internal/engine/porthop.go`) beneath KCP + Reed-Solomon FEC + Smux.
  - Every packet carries a 16-byte HMAC-SHA256 obfuscated header (`[4B salt][8B XOR-masked sessionID][4B authTag]`) with zero static magic bytes on the wire.
  - **Listener**: Binds a deterministic pool of UDP ports (`tunnel_port .. tunnel_port + port_hop_ports - 1`, default 8 ports) and fans all incoming packets into a single KCP session keyed by authenticated `sessionID`. Replies are transmitted from the exact server UDP socket (`dstPort`) and to the latest client `srcPort` most recently validated for that session, maintaining full stateful NAT compatibility (including 1:1 cloud NATs such as Oracle Cloud / AWS).
  - **Dialer**: Starts on `basePort` for instant connectivity, then opens a fresh ephemeral local UDP socket (new `srcPort`) and advances `dstPort` across the hop pool every `15s`, keeping the prior socket draining in the background for `4s` so zero packets drop during rotation. Includes automatic fallback to `basePort` (while continuing `srcPort` rotation) if a cloud security list only opened the primary port.
  - **Firewall**: `portbridge-firewall` opens the peer-locked UDP port range `TPORT:ENDPORT` automatically and purges rules cleanly by tunnel comment tag.

### 2. SplitHTTP / XHTTP (`xhttp` & `xhttp-cdn` / `transport = xhttp`)
- **Status**: ✅ Implemented (`v0.17.58`)
- **Problem Solved**: Stateful DPI systems detect or throttle WebSocket (`Upgrade: websocket` / `101 Switching Protocols`) and long-lived raw TLS byte counters, while many CDNs require special enterprise/dashboard toggles for gRPC.
- **Architecture**:
  - Splits downlink and uplink into completely ordinary, standard HTTP/1.1 HTTPS requests (`internal/engine/xhttp.go`) with zero `Upgrade` headers:
    - **Downlink (`GET <path>/<streamID>`)**: Standard HTTPS `GET` returning `200 OK` with `Transfer-Encoding: chunked`, anti-buffering headers (`Cache-Control: no-store, no-transform`, `X-Accel-Buffering: no`), and randomized header padding to flush CDN proxies immediately.
    - **Uplink (`POST <path>/<streamID>/<seq>`)**: Standard HTTPS `POST` requests with coalesced request bodies and sequence-ordered reassembly on the server. Automatically rotates uplink keep-alive TLS sockets every 64 requests (well below Cloudflare's 100-request HTTP/1.1 keep-alive cap) and retries transparently on stale keep-alive sockets.
  - Works in **Direct**, **Reverse**, **IPv4**, **IPv6**, **Stealth (uTLS + ClientHello Fragmentation + ECH)**, **Real-Site Cover**, and **Cloudflare / Any CDN (`xhttp-cdn`)** without needing gRPC enabled.

---

## Phase 2 (Planned — Next After Live Testing of Phase 1)

### 3. Asymmetric Dual-Path Hybrid (`asymmetric` — Separate Uplink & Downlink Transports)
- **Status**: 📋 Planned (Phase 2)
- **Problem Solved**: Cross-border filtering is strongly asymmetric — Direct outbound traffic (`Relay -> Foreign`) faces strict DPI / byte-cap freezes, whereas Reverse inbound traffic (`Foreign -> Relay`) or UDP/Spoofed traffic often runs at full line rate. Conversely, CDNs guarantee unblockable upload reachability while direct/reverse paths offer much lower download latency and higher throughput.
- **Architecture**:
  - Pair two independent transport legs inside a unified `net.Conn` / `Mux` carrier:
    - **Uplink Leg (`Relay -> Foreign`)**: e.g. `xhttp-cdn` / `wss-cdn` / `split-tls`.
    - **Downlink Leg (`Foreign -> Relay`)**: e.g. Reverse `kcp-hop`, Reverse `tls`, or `ip-spoof`.
  - Session pairing token binds both directional pipes at the `smux` carrier layer.

### 4. Native QUIC / HTTP/3 Masquerade (`h3` & `h3-cdn`)
- **Status**: 📋 Planned (Phase 2)
- **Problem Solved**: Over 30% of real browser web traffic (Chrome, YouTube, Instagram, Cloudflare) now uses HTTP/3 over UDP `:443`.
- **Architecture**:
  - Real QUIC v1 handshake with genuine TLS 1.3 + HTTP/3 `SETTINGS` frames and `CONNECT` / datagram streams (`quic-go`), eliminating TCP head-of-line blocking while blending into ordinary UDP `:443` browser traffic and supporting Cloudflare HTTP/3 edge proxying.
  - Built-in QUIC connection migration support (survives NAT rebinds and port rotation natively).

---

## Phase 3 (Planned — Future Rollout)

### 5. WebRTC / STUN + DTLS-SRTP Video-Call Disguise (`webrtc`)
- **Status**: 📋 Planned (Phase 3)
- **Problem Solved**: Even when ISPs block QUIC (`UDP :443`) to force browsers onto TCP, they almost never block WebRTC (`STUN Binding` + `DTLS-SRTP`) because doing so breaks WhatsApp, Telegram, Google Meet, Zoom, and corporate VoIP calls.
- **Architecture**:
  - Opens every UDP flow with RFC 5389 `STUN Binding Request / Success Response` (`0x2112A442` magic cookie) followed by RTP/SRTP-framed encrypted KCP+FEC packets mimicking a live video/voice call's packet size and cadence.

### 6. "Twin-Path" 1+1 Packet Duplication (`twin_path` Gaming Mode)
- **Status**: 📋 Planned (Phase 3)
- **Problem Solved**: Competitive gaming, trading, and live voice/video suffer whenever a single packet drops and waits 1 RTT for retransmission, or when FEC loses more packets in a micro-burst than parity shards can recover.
- **Architecture**:
  - Transmits each small latency-sensitive packet (`<= 600B`) simultaneously across two independent paths/ports (e.g. two UDP ports or UDP + TCP); the receiver accepts whichever copy arrives first and discards the duplicate by sequence bitmap, delivering **0 ms jitter spikes** even under 5–10% packet loss.
