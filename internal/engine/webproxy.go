package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultOutboundIranDomains lists Iranian banking/Shaparak payment networks,
// SMS gateways, and domestic services that require an Iranian source IP.
const DefaultOutboundIranDomains = "*.ir,*.shaparak.ir,*.bmi.ir,*.mellat.ir,*.zarinpal.com,*.zibal.ir,*.idpay.ir,*.nextpay.org,*.payping.ir,*.sep.ir,*.pec.ir,*.asanpardakht.ir,*.sadad.co.ir,*.samanpr.ir,*.kavenegar.com,*.melipayamak.com,*.sms.ir,*.ippanel.com,*.farazsms.com,*.ghasedak.me,*.mediana.ir,*.niksms.com,*.parsgreen.com,*.raygansms.com,*.post.ir,*.torob.com,*.emalls.ir,*.digikala.com,*.snapp.ir,*.snapppay.ir,*.tapsi.ir,*.nobitex.ir,*.wallex.ir,*.bitpin.ir"

// DefaultOutboundBypassDomains lists international APIs (Telegram, WordPress.org,
// Google, Cloudflare, etc.) that must always exit directly from the foreign VPS IP.
const DefaultOutboundBypassDomains = "*.telegram.org,api.telegram.org,t.me,*.t.me,*.wordpress.org,*.w.org,*.woocommerce.com,*.github.com,*.githubusercontent.com,*.googleapis.com,*.google.com,*.gstatic.com,*.cloudflare.com,*.stripe.com,*.paypal.com,*.openai.com,*.anthropic.com"

// OutboundCheckHost is a synthetic hostname handled directly by the Iran Edge
// so the Panel's "Test Outbound Routing" button can deterministically verify
// end-to-end tunnel routing and report the Iran Edge IP.
const OutboundCheckHost = "portbridge-iran-check.ir"

// allowLoopbackProxyForTest permits the edge outbound proxy to dial 127.0.0.1
// during unit tests. In production this is always false so the proxy cannot be
// used to reach internal loopback/private services on the Iran server.
var allowLoopbackProxyForTest bool

// ShouldRouteViaIran decides whether an outbound connection to host should be
// tunnelled through the Iran edge server (true) or dialled directly from the
// foreign origin server (false).
func ShouldRouteViaIran(host string, cfg *Config) bool {
	h := normalizeProxyHost(host)
	if h == "" || h == "localhost" {
		return false
	}
	if h == OutboundCheckHost {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	}

	customBypass := ""
	customIran := ""
	if cfg != nil {
		customBypass = strings.TrimSpace(cfg.OutboundBypassDomains)
		customIran = strings.TrimSpace(cfg.OutboundIranDomains)
	}

	// 1. Explicit custom bypass list takes highest priority.
	if customBypass != "" && hostMatchesDomainList(h, customBypass) {
		return false
	}
	// 2. Explicit custom Iran list takes next priority.
	if customIran != "" && hostMatchesDomainList(h, customIran) {
		return true
	}
	// 3. Built-in bypass list (Telegram, WordPress.org, etc.).
	if hostMatchesDomainList(h, DefaultOutboundBypassDomains) {
		return false
	}
	// 4. In "all" mode, everything else routes via Iran.
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.OutboundProxyMode), "all") {
		return true
	}
	// 5. Built-in Iran gateways & .ir domains.
	return hostMatchesDomainList(h, DefaultOutboundIranDomains)
}

func normalizeProxyHost(host string) string {
	h := strings.TrimSpace(host)
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	return h
}

func hostMatchesDomainList(host, rawList string) bool {
	fields := strings.FieldsFunc(rawList, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	for _, item := range fields {
		pat := strings.ToLower(strings.TrimSpace(item))
		if pat == "" {
			continue
		}
		pat = strings.TrimPrefix(pat, "https://")
		pat = strings.TrimPrefix(pat, "http://")
		if idx := strings.IndexByte(pat, '/'); idx >= 0 {
			pat = pat[:idx]
		}
		if sh, _, err := net.SplitHostPort(pat); err == nil {
			pat = sh
		}
		pat = strings.TrimSuffix(pat, ".")
		if pat == "" {
			continue
		}
		if pat == "*" {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			root := pat[2:]
			if root != "" && (host == root || strings.HasSuffix(host, "."+root)) {
				return true
			}
			continue
		}
		if strings.HasPrefix(pat, ".") {
			root := pat[1:]
			if root != "" && (host == root || strings.HasSuffix(host, "."+root)) {
				return true
			}
			continue
		}
		if host == pat || strings.HasSuffix(host, "."+pat) {
			return true
		}
	}
	return false
}

// startOutboundProxy starts the local HTTP/HTTPS CONNECT & SOCKS5 proxy on the
// foreign origin server (127.0.0.1:<OutboundProxyPort>) when OutboundProxy is enabled.
func startOutboundProxy(ctx context.Context, o *origin) (net.Listener, error) {
	if !o.cfg.OutboundProxy {
		return nil, nil
	}
	port := o.cfg.OutboundProxyPort
	if port <= 0 {
		port = 18080
	}
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listening on local outbound proxy %s: %w", bindAddr, err)
	}
	log.Printf("[%s] smart website outbound proxy listening on %s (mode=%s)",
		o.cfg.Name, bindAddr, o.cfg.OutboundProxyMode)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go o.serveLocalProxyConn(ctx, c)
		}
	}()

	return ln, nil
}

func (o *origin) serveLocalProxyConn(ctx context.Context, client net.Conn) {
	o.wg.Add(1)
	defer o.wg.Done()
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(client)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	if first[0] == 0x05 {
		o.serveSOCKS5ProxyConn(ctx, client, br)
		return
	}
	o.serveHTTPProxyConn(ctx, client, br)
}

func (o *origin) dialOutboundTarget(ctx context.Context, host, port string) (net.Conn, string, error) {
	target := net.JoinHostPort(host, port)
	if ShouldRouteViaIran(host, o.cfg) {
		c, err := o.dialViaEdge(ctx, target)
		return c, "iran", err
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", target)
	return c, "direct", err
}

func (o *origin) serveHTTPProxyConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		host, port, err := splitHostPortDefault(req.Host, "443")
		if err != nil {
			_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			return
		}
		remote, route, err := o.dialOutboundTarget(ctx, host, port)
		if err != nil {
			msg := fmt.Sprintf("PortBridge outbound proxy (%s) could not reach %s:%s: %v\n", route, host, port, err)
			_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nX-PortBridge-Route: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				route, len(msg), msg)
			return
		}
		defer remote.Close()

		_ = client.SetDeadline(time.Time{})
		_, err = fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\nX-PortBridge-Route: %s\r\n\r\n", route)
		if err != nil {
			return
		}
		if br.Buffered() > 0 {
			buf := make([]byte, br.Buffered())
			n, _ := br.Read(buf)
			if n > 0 {
				if _, err := remote.Write(buf[:n]); err != nil {
					return
				}
			}
		}
		_ = relay(client, remote)
		return
	}

	// Plain HTTP proxy request (e.g. GET http://example.ir/path HTTP/1.1)
	rawHost := req.URL.Host
	if rawHost == "" {
		rawHost = req.Host
	}
	host, port, err := splitHostPortDefault(rawHost, "80")
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}

	remote, route, err := o.dialOutboundTarget(ctx, host, port)
	if err != nil {
		msg := fmt.Sprintf("PortBridge outbound proxy (%s) could not reach %s:%s: %v\n", route, host, port, err)
		_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nX-PortBridge-Route: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			route, len(msg), msg)
		return
	}
	defer remote.Close()

	_ = client.SetDeadline(time.Time{})
	req.URL.Scheme = ""
	req.URL.Host = ""
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Set("Connection", "close")

	if err := req.Write(remote); err != nil {
		return
	}
	_ = relay(client, remote)
}

func (o *origin) serveSOCKS5ProxyConn(ctx context.Context, client net.Conn, br *bufio.Reader) {
	// Greeting: [VER=0x05][NMETHODS][METHODS...]
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Reply: no authentication required (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: [VER=0x05][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHdr); err != nil || reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 { // Only CONNECT (0x01)
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch reqHdr[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		dom := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(br, dom); err != nil {
			return
		}
		host = string(dom)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))

	remote, _, err := o.dialOutboundTarget(ctx, host, port)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	_ = client.SetDeadline(time.Time{})
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			if _, err := remote.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	_ = relay(client, remote)
}

func splitHostPortDefault(input, defaultPort string) (string, string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", "", errors.New("empty host")
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
		if h == "" || p == "" {
			return "", "", errors.New("invalid host:port")
		}
		return h, p, nil
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	if s == "" {
		return "", "", errors.New("empty host")
	}
	return s, defaultPort, nil
}

// dialViaEdge opens a reverse stream to the Iran edge server and asks it to
// dial target (host:port) from the Iran IP.
func (o *origin) dialViaEdge(ctx context.Context, target string) (net.Conn, error) {
	if len(target) == 0 || len(target) > 512 {
		return nil, fmt.Errorf("invalid outbound target %q", target)
	}

	var stream net.Conn
	var err error
	if o.links != nil {
		stream, err = o.links.openReverse(ctx.Done())
	} else if o.cfg.Mode == ModeReverse && o.routes != nil {
		stream, err = o.dialEdgeWithPurpose(authPurposeOutboundProxy)
	} else {
		return nil, errors.New("outbound proxy requires shared connections (mux = on) or reverse mode")
	}
	if err != nil {
		return nil, fmt.Errorf("opening reverse stream to Iran server: %w", err)
	}

	_ = stream.SetDeadline(time.Now().Add(12 * time.Second))

	frame := make([]byte, 3+len(target))
	frame[0] = msgOutboundDial
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(target)))
	copy(frame[3:], target)

	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("sending outbound dial request to Iran server: %w", err)
	}

	var reply [1]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("waiting for Iran server outbound dial reply: %w", err)
	}

	switch reply[0] {
	case msgAck:
		_ = stream.SetDeadline(time.Time{})
		return stream, nil
	case 0x00:
		var lenBuf [2]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err == nil {
			errLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if errLen > 0 && errLen <= 1024 {
				msg := make([]byte, errLen)
				if _, err := io.ReadFull(stream, msg); err == nil {
					_ = stream.Close()
					return nil, fmt.Errorf("Iran server could not reach %s: %s", target, string(msg))
				}
			}
		}
		_ = stream.Close()
		return nil, fmt.Errorf("Iran server refused outbound dial to %s", target)
	default:
		_ = stream.Close()
		return nil, fmt.Errorf("unexpected outbound dial reply 0x%02x from Iran server", reply[0])
	}
}

func (o *origin) dialEdgeWithPurpose(purpose byte) (net.Conn, error) {
	raw, idx, err := o.routes.dialIdx(10 * time.Second)
	if err != nil {
		return nil, err
	}
	tuneSocket(raw)
	c, err := wrapDialPurpose(raw, o.routes.routeConfig(idx), purpose)
	if err != nil {
		_ = raw.Close()
		o.routes.handshakeFailed(idx, err)
		return nil, err
	}
	if err := sendAuthPurpose(c, o.cfg.secret, purpose); err != nil {
		_ = c.Close()
		o.routes.handshakeFailed(idx, err)
		return nil, err
	}
	o.routes.handshakeOK(idx)
	return c, nil
}

// serveOutboundStream runs on the Iran edge server and handles an outbound
// proxy stream initiated by the foreign origin server.
func (e *edge) serveOutboundStream(c net.Conn) {
	e.wg.Add(1)
	defer e.wg.Done()
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(12 * time.Second))

	var hdr [3]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != msgOutboundDial {
		return
	}
	targetLen := int(binary.BigEndian.Uint16(hdr[1:3]))
	if targetLen <= 0 || targetLen > 512 {
		return
	}
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(c, targetBuf); err != nil {
		return
	}
	target := string(targetBuf)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		writeOutboundDialError(c, "invalid target host:port")
		return
	}

	// Synthetic self-check endpoint for the Panel's "Test Outbound Routing" button
	if strings.EqualFold(host, OutboundCheckHost) {
		_, _ = c.Write([]byte{msgAck})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		_, _ = http.ReadRequest(br)
		iranIP := e.cfg.LocalIP
		if iranIP == "" {
			iranIP = "iran-edge"
		}
		payload, _ := json.Marshal(map[string]any{
			"ok":          true,
			"route":       "iran",
			"iran_ip":     iranIP,
			"edge_tunnel": e.cfg.Name,
		})
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-PortBridge-Route: iran\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(payload), string(payload))
		_, _ = io.WriteString(c, resp)
		return
	}

	dialAddr, err := resolveSafeOutboundTarget(host, port)
	if err != nil {
		writeOutboundDialError(c, err.Error())
		return
	}

	remote, err := net.DialTimeout("tcp", dialAddr, 10*time.Second)
	if err != nil {
		writeOutboundDialError(c, err.Error())
		return
	}
	defer remote.Close()

	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte{msgAck}); err != nil {
		return
	}

	atomic.AddInt64(&e.st.activeSessions, 1)
	defer atomic.AddInt64(&e.st.activeSessions, -1)

	_ = relay(c, remote)
}

func writeOutboundDialError(c net.Conn, msg string) {
	if len(msg) > 512 {
		msg = msg[:512]
	}
	buf := make([]byte, 3+len(msg))
	buf[0] = 0x00
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(msg)))
	copy(buf[3:], msg)
	_ = c.SetWriteDeadline(time.Now().Add(4 * time.Second))
	_, _ = c.Write(buf)
}

func resolveSafeOutboundTarget(host, port string) (string, error) {
	pNum, err := strconv.Atoi(port)
	if err != nil || pNum < 1 || pNum > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !allowLoopbackProxyForTest && isBlockedOutboundIP(ip) {
			return "", fmt.Errorf("refusing to dial internal/private address %s on Iran server", ip.String())
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolving %s on Iran server: %w", host, err)
	}
	for _, ipAddr := range ips {
		if !allowLoopbackProxyForTest && isBlockedOutboundIP(ipAddr.IP) {
			return "", fmt.Errorf("domain %s resolves to internal/private address %s", host, ipAddr.IP.String())
		}
	}
	return net.JoinHostPort(ips[0].IP.String(), port), nil
}

func isBlockedOutboundIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
