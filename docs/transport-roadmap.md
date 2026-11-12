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

## Phase 2 (Implemented in `v0.17.59`)

### 3. Asymmetric Dual-Path Hybrid (`asymmetric` & `asymmetric-cdn` / `asymmetric = on`)
- **Status**: ✅ Implemented (`v0.17.59`)
- **Problem Solved**: Cross-border filtering is strongly asymmetric — Direct outbound traffic (`Relay -> Foreign`) faces strict DPI / byte-cap freezes, whereas Reverse inbound traffic (`Foreign -> Relay`) or UDP Port-Hopping traffic runs at full line rate. Conversely, CDNs guarantee unblockable upload reachability while reverse direct paths deliver dramatically lower download latency and multi-hundred-Mbps download throughput.
- **Architecture**:
  - Pairs two independent directional transport legs inside a unified `net.Conn` / `Mux` carrier (`internal/engine/asymmetric.go`):
    - **Uplink Leg (`Relay -> Foreign`)**: `xhttp` (Direct Stealth SplitHTTP, default), `xhttp` via Cloudflare/CDN (`asymmetric-cdn`), `split`, `wss`, `tls`, or `h3`.
    - **Downlink Leg (`Foreign -> Relay`)**: Reverse `kcp-hop` (8-port UDP Port-Hopping + Reed-Solomon FEC, default), `kcp`, `webrtc`, `h3`, or `tls`.
  - **Cryptographic Session Pairing**: 64-byte HMAC-SHA256 + timestamp + replay-guarded prefaces (`ASYMU1` on Uplink, `ASYMD1` on Reverse Downlink) with a 1-byte `0xA5` ready ACK before end-to-end `v2` purpose authentication.
  - **Automatic UDP-Blackhole Fallback**: `asymEdgeRuntime` listens simultaneously for Port-Hop KCP, WebRTC, HTTP/3, and TLS-over-TCP on the same port. If an ISP or cloud firewall blackholes UDP packets (`3s` ACK timeout), `asymOriginRuntime` automatically dials Reverse TLS over TCP on the exact same port and caches the TCP fallback for `2m` so zero manual reconfiguration is needed.
  - **Smart Connection Finder & Auto-Heal**: Synthesizes `direct-asymmetric` and `direct-asymmetric-cdn` from measured directional speeds and allows Auto-Heal to fail over to them automatically.

### 4. Native QUIC / HTTP/3 Masquerade (`h3` & `h3-cdn` / `transport = h3`)
- **Status**: ✅ Implemented (`v0.17.59`)
- **Problem Solved**: Over 30% of real browser web traffic (Chrome, YouTube, Instagram, Cloudflare) uses HTTP/3 over UDP, eliminating TCP head-of-line blocking and TCP `RST` injection.
- **Architecture**:
  - Genuine RFC 9000 QUIC v1 + TLS 1.3 (`ALPN: h3`) + RFC 9114 HTTP/3 transport (`internal/engine/h3.go`, powered by `quic-go`):
    - **Direct & Reverse (`h3`)**: Full-duplex HTTP/3 `POST` request stream with HMAC-SHA256 `X-Session-Token` + server hello proof, serving a realistic nginx `404 Not Found` HTML page to unauthenticated active probes.
    - **Cloudflare / CDN (`h3-cdn`)**: Runs SplitHTTP/XHTTP over HTTP/3 (`GET` downlink stream + sequenced `POST` uplink streams) from Relay to Cloudflare's UDP `:443` QUIC edge, while `h3Listen` binds a combined UDP HTTP/3 + TCP TLS listener on the Origin server so Cloudflare can forward standard HTTP/1.1 `GET` + `POST` over TLS/TCP with zero special origin settings.
  - **Single-Port UDP Demultiplexer (`demuxQUICAndPacketConn`)**: Classifies RFC 9000 `>=1200B` Long Header Initial packets so HTTP/3, WebRTC, Twin-Path, Port-Hop KCP, and IP-Spoof KCP coexist on a single UDP socket in both `ProbeListener` and `asymEdgeRuntime`.

---

## Phase 3 (Implemented — Next Live Testing Rollout)

### 5. WebRTC Video-Call Disguise (`webrtc` / `transport = webrtc`)
- **Status**: ✅ Implemented (Phase 3)
- **Problem Solved**: Even when ISPs block QUIC (`UDP :443`) to force browsers onto TCP, they almost never block WebRTC (`STUN Binding` + `SRTP` media) because doing so breaks WhatsApp, Telegram, Google Meet, Zoom, and corporate VoIP calls.
- **Architecture**:
  - **RFC 5389 ICE STUN Handshake & RFC 7675 Consent Checks (`internal/engine/webrtc.go`)**: Opens every UDP flow with a genuine STUN Binding Request (`0x0001`, magic cookie `0x2112A442`) carrying `USERNAME` (`ufrag:ufrag`), `ICE-CONTROLLING` (8-byte XOR-masked `sessionID`), `PRIORITY`, PSK-derived HMAC-SHA1 `MESSAGE-INTEGRITY`, and CRC-32 `FINGERPRINT` (`XOR 0x5354554E`), answered by a genuine STUN Binding Success Response (`0x0101`) with `XOR-MAPPED-ADDRESS` (IPv4 & IPv6) and refreshed every `12s` via ICE consent checks. Unauthenticated UDP scanners are silently dropped.
  - **RFC 3550 RTP v2 + RFC 3711 SRTP Framing**: Encapsulates KCP + Reed-Solomon FEC + Smux frames inside genuine RTP v2 headers (`0x80`, dynamic `PT=111` Opus audio for `<=240B` packets and `PT=96` VP8 video for `>240B` packets, monotonic `uint16` sequence numbers, 90 kHz media clock timestamps, and deterministic session SSRC) with a 16-byte obfuscated session header and 4-byte constant-time HMAC-SHA256 SRTP authentication tag.
  - Composes seamlessly with **Direct**, **Reverse**, **IPv4**, **IPv6**, **Port-Hopping (`port_hop = on`)**, **Twin-Path (`twin_path = on`)**, and **Asymmetric Reverse Downlink (`asym_downlink = webrtc`)**.

### 6. "Twin-Path" 1+1 Packet Duplication (`twin` / `twin_path = on`)
- **Status**: ✅ Implemented (Phase 3)
- **Problem Solved**: Competitive gaming, trading, and interactive sessions suffer whenever a single UDP packet drops or hits a congested ECMP queue and waits 1 RTT for retransmission, or when a micro-burst exceeds FEC parity shards.
- **Architecture**:
  - **Selective Dual-Socket 1+1 Duplication (`internal/engine/twinpath.go`)**: Transmits latency-critical packets (`<= TwinPathMaxBytes`, default `700B`: game ticks, handshakes, ACKs, DNS, SSH keystrokes) simultaneously across **two independent local ephemeral UDP sockets** targeting `[tunnel_port, tunnel_port + 1]` (or two distinct ports in the `port_hop_ports` pool when `port_hop = on`). Full-MTU bulk segments (`> 700B`) travel on a single leg so downloads run at full line speed without 2x upload overhead.
  - **O(1) 2048-Packet Sliding Sequence Bitmap (`twinSeqWindow`)**: Every packet carries a zero-magic 20-byte HMAC-SHA256 authenticated header (`[4B salt][12B XOR-masked sessionID || uint32 seq][4B tag]`). Whichever copy arrives first on either socket is delivered immediately while the trailing copy is discarded in O(1) time with zero allocations.
  - **Automatic Single-Port Fallback & Firewall Integration**: If a cloud security list only opened `tunnel_port` and drops `tunnel_port + 1`, Leg 1 automatically falls back to `dstPort = tunnel_port` while retaining two independent local `srcPort`s for ECMP diversity. `portbridge-firewall` automatically opens and peer-locks `TPORT:(TPORT+1)` on UDP when `twin_path = on`.
