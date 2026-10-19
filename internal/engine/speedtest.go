package engine

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runSpeedtestServer handles the server side of the in-tunnel speedtest.
func runSpeedtestServer(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))

	// A person running a speed test starts with the latency phase and is worth
	// one line in the log. The routine path check that tunnels run on themselves
	// every few seconds starts with the download phase and is not: logging it
	// would put a line in the journal every quarter of a minute, for ever.
	announced := false

	buf := make([]byte, 32*1024)
	_, _ = rand.Read(buf[:256])
	for i := 256; i < len(buf); i++ {
		buf[i] = buf[i%256] ^ byte(i)
	}

	for {
		var phase [1]byte
		if _, err := io.ReadFull(c, phase[:]); err != nil {
			return
		}

		switch phase[0] {
		case 0x01: // Latency / Ping phase
			if !announced {
				announced = true
				log.Printf("[speedtest-server] speed test from %s", c.RemoteAddr())
			}
			const numSamples = 1
			for i := 0; i < numSamples; i++ {
				var ts [8]byte
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.ReadFull(c, ts[:]); err != nil {
					return
				}
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(ts[:]); err != nil {
					return
				}
			}
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))

		case 0x02: // Download phase: Server pumps data to Client
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			var sizeBuf [4]byte
			if _, err := io.ReadFull(c, sizeBuf[:]); err != nil {
				return
			}
			total := int64(binary.BigEndian.Uint32(sizeBuf[:]))
			// Send Ready ACK so client knows server received download request
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte{0x00}); err != nil {
				return
			}
			sent := int64(0)
			for sent < total {
				toWrite := int64(len(buf))
				if rem := total - sent; rem < toWrite {
					toWrite = rem
				}
				_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
				n, err := c.Write(buf[:toWrite])
				if err != nil {
					return
				}
				sent += int64(n)
			}

		case 0x03: // Upload phase: Server receives data from Client
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			var sizeBuf [4]byte
			if _, err := io.ReadFull(c, sizeBuf[:]); err != nil {
				return
			}
			total := int64(binary.BigEndian.Uint32(sizeBuf[:]))
			// Send Ready ACK so client knows server is ready to receive
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte{0x00}); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, c, total); err != nil {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte{0x00}); err != nil {
				return
			}

		case 0x04: // Done
			return
		default:
			return
		}
	}
}

// runSpeedtestClient runs the client side of the in-tunnel speedtest.
func runSpeedtestClient(c net.Conn, cfg *Config, out io.Writer, sizeMB ...float64) error {
	if out == nil {
		out = os.Stdout
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))

	fmt.Fprintf(out, "\n🚀 PortBridge Speed Test: %s\n", cfg.Name)
	fmt.Fprintf(out, "   Mode: %s | Role: %s | Transport: %s\n", cfg.Mode, cfg.Role, describeTransport(cfg))
	fmt.Fprintf(out, "   Endpoint: %s\n\n", cfg.TunnelAddr)

	// Phase 1: Latency & Jitter
	fmt.Fprintf(out, "⏱️  Testing latency and round-trip time...\n")
	if _, err := c.Write([]byte{0x01}); err != nil {
		return fmt.Errorf("ping phase start: %w", err)
	}

	var rtts []time.Duration
	const numSamples = 1
	for i := 0; i < numSamples; i++ {
		var ts [8]byte
		now := time.Now()
		binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(ts[:]); err != nil {
			return fmt.Errorf("ping send: %w", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		var echo [8]byte
		if _, err := io.ReadFull(c, echo[:]); err != nil {
			return fmt.Errorf("ping reply: %w", err)
		}
		rtt := time.Since(now)
		rtts = append(rtts, rtt)
	}
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))

	avgRTT := rtts[0]
	jitterMS := 0.0

	// If the underlying connection is KCP, fetch kernel transport statistics
	type kcpStats interface {
		GetSRTT() int32
		GetSRTTVar() int32
	}
	if ks, ok := c.(kcpStats); ok {
		if srtt := ks.GetSRTT(); srtt > 0 {
			avgRTT = time.Duration(srtt) * time.Millisecond
			jitterMS = float64(ks.GetSRTTVar())
		}
	}

	fmt.Fprintf(out, "   RTT: %.2f ms | Jitter: %.2f ms\n\n",
		float64(avgRTT)/float64(time.Millisecond),
		jitterMS)

	// Phase 2 & 3: Download and Upload Tests
	mb := 1.0
	if len(sizeMB) > 0 && sizeMB[0] > 0 {
		mb = sizeMB[0]
	}
	testSize := uint32(mb * 1024 * 1024)
	if testSize == 0 {
		testSize = 1024 * 1024
	}

	readBuf := make([]byte, 32*1024)
	sendChunk := make([]byte, 32*1024)
	_, _ = rand.Read(sendChunk[:128])
	for i := 128; i < len(sendChunk); i++ {
		sendChunk[i] = sendChunk[i%128] ^ byte(i)
	}

	runServerToClient := func(sz uint32) (int64, time.Duration, error) {
		hdr := make([]byte, 5)
		hdr[0] = 0x02
		binary.BigEndian.PutUint32(hdr[1:], sz)
		_ = c.SetDeadline(time.Now().Add(120 * time.Second))
		reqStart := time.Now()
		if _, err := c.Write(hdr); err != nil {
			return 0, 0, fmt.Errorf("download phase start: %w", err)
		}
		var ready [1]byte
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(c, ready[:]); err != nil {
			return 0, 0, fmt.Errorf("download ready ACK: %w", err)
		}
		start := time.Now()
		var nRead int64
		var rErr error
		for nRead < int64(sz) {
			toRead := int64(len(readBuf))
			if rem := int64(sz) - nRead; rem < toRead {
				toRead = rem
			}
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := c.Read(readBuf[:toRead])
			if n > 0 {
				nRead += int64(n)
			}
			if err != nil {
				rErr = err
				break
			}
		}
		elapsed := time.Since(start)
		totalElapsed := time.Since(reqStart)
		netElapsed := totalElapsed - avgRTT
		if minNet := time.Duration(float64(totalElapsed) * 0.5); netElapsed < minNet {
			netElapsed = minNet
		}
		if netElapsed > elapsed {
			elapsed = netElapsed
		}
		return nRead, elapsed, rErr
	}

	runClientToServer := func(sz uint32) (int64, time.Duration, error) {
		hdr := make([]byte, 5)
		hdr[0] = 0x03
		binary.BigEndian.PutUint32(hdr[1:], sz)
		_ = c.SetDeadline(time.Now().Add(120 * time.Second))
		if _, err := c.Write(hdr); err != nil {
			return 0, 0, fmt.Errorf("upload phase start: %w", err)
		}
		var ready [1]byte
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(c, ready[:]); err != nil {
			return 0, 0, fmt.Errorf("upload ready ACK: %w", err)
		}
		start := time.Now()
		var nSent int64
		var wErr error
		for nSent < int64(sz) {
			toWrite := int64(len(sendChunk))
			if rem := int64(sz) - nSent; rem < toWrite {
				toWrite = rem
			}
			_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
			n, err := c.Write(sendChunk[:toWrite])
			if n > 0 {
				nSent += int64(n)
			}
			if err != nil {
				wErr = err
				break
			}
		}
		var doneAck [1]byte
		if wErr == nil {
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			if _, err := io.ReadFull(c, doneAck[:]); err != nil {
				wErr = err
			}
		}
		elapsed := time.Since(start)
		if elapsed > avgRTT && avgRTT > 0 {
			adj := elapsed - avgRTT/2
			if minAdj := time.Duration(float64(elapsed) * 0.65); adj < minAdj {
				adj = minAdj
			}
			elapsed = adj
		}
		return nSent, elapsed, wErr
	}

	// In Reverse mode when Origin (Foreign) dials Edge (Relay), Client->Server is
	// Foreign->Relay (User Download) and Server->Client is Relay->Foreign (User Upload).
	reverseOriginDial := cfg != nil && cfg.Mode == ModeReverse && cfg.Role == RoleOrigin
	doWarmup := cfg != nil && !cfg.AntiFreeze && testSize >= 256*1024
	warmupSz := uint32(256 * 1024)
	if cfg != nil && cfg.Transport == TransportICMP {
		warmupSz = 768 * 1024
	}

	fmt.Fprintf(out, "⬇️  Testing download throughput (%.2f MB)...\n", float64(testSize)/(1024*1024))
	var dlBytes int64
	var dlElapsed time.Duration
	var dlErr error
	if reverseOriginDial {
		if doWarmup {
			_, _, _ = runClientToServer(warmupSz)
		}
		dlBytes, dlElapsed, dlErr = runClientToServer(testSize)
	} else {
		if doWarmup {
			_, _, _ = runServerToClient(warmupSz)
		}
		dlBytes, dlElapsed, dlErr = runServerToClient(testSize)
	}
	if dlBytes == 0 && dlErr != nil {
		return fmt.Errorf("download test: %w", dlErr)
	}
	dlMBps := (float64(dlBytes) / (1024 * 1024)) / dlElapsed.Seconds()
	dlMbps := (float64(dlBytes) * 8 / 1_000_000) / dlElapsed.Seconds()
	if dlErr != nil {
		fmt.Fprintf(out, "   Download: %.2f MB/s (%.1f Mbps) (partial: %d/%d bytes in %.2fs: %v)\n\n", dlMBps, dlMbps, dlBytes, testSize, dlElapsed.Seconds(), dlErr)
	} else {
		fmt.Fprintf(out, "   Download: %.2f MB/s (%.1f Mbps) in %.2fs\n\n", dlMBps, dlMbps, dlElapsed.Seconds())
	}

	fmt.Fprintf(out, "⬆️  Testing upload throughput (%.2f MB)...\n", float64(testSize)/(1024*1024))
	var ulBytes int64
	var ulElapsed time.Duration
	var ulErr error
	if reverseOriginDial {
		if doWarmup {
			_, _, _ = runServerToClient(warmupSz)
		}
		ulBytes, ulElapsed, ulErr = runServerToClient(testSize)
	} else {
		if doWarmup {
			_, _, _ = runClientToServer(warmupSz)
		}
		ulBytes, ulElapsed, ulErr = runClientToServer(testSize)
	}
	if ulBytes == 0 && ulErr != nil {
		return fmt.Errorf("upload test: %w", ulErr)
	}
	ulMBps := (float64(ulBytes) / (1024 * 1024)) / ulElapsed.Seconds()
	ulMbps := (float64(ulBytes) * 8 / 1_000_000) / ulElapsed.Seconds()
	if ulErr != nil {
		fmt.Fprintf(out, "   Upload: %.2f MB/s (%.1f Mbps) (partial: %d/%d bytes in %.2fs: %v)\n\n", ulMBps, ulMbps, ulBytes, testSize, ulElapsed.Seconds(), ulErr)
	} else {
		fmt.Fprintf(out, "   Upload: %.2f MB/s (%.1f Mbps) in %.2fs\n\n", ulMBps, ulMbps, ulElapsed.Seconds())
	}

	// Finish
	_, _ = c.Write([]byte{0x04})

	fmt.Fprintln(out, "================== Speed Test Summary ==================")
	fmt.Fprintf(out, " Link:        %s -> %s\n", cfg.Name, cfg.TunnelAddr)
	fmt.Fprintf(out, " RTT:         %.2f ms (Jitter: %.2f ms)\n",
		float64(avgRTT)/float64(time.Millisecond),
		jitterMS)
	fmt.Fprintf(out, " Download:    %.1f Mbps (%.2f MB/s)\n", dlMbps, dlMBps)
	fmt.Fprintf(out, " Upload:      %.1f Mbps (%.2f MB/s)\n", ulMbps, ulMBps)
	fmt.Fprintln(out, "========================================================")
	return nil
}

func CmdSpeedtest(args []string) {
	fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to the tunnel config file")
	sizeMB := fs.Float64("size", 1.0, "Transfer size in megabytes (default 1.0, e.g. 0.5 for 512KB, 0.25 for 256KB)")

	// Allow positional tunnel name before or after flags, e.g. "speedtest kcp1 -size 0.25"
	var positional string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") && positional == "" {
			positional = args[i]
		} else {
			flagArgs = append(flagArgs, args[i])
		}
	}
	_ = fs.Parse(flagArgs)

	path := *configPath
	if path == "" {
		path = positional
	}
	if path == "" && fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "speedtest: tunnel name or -config <path> is required")
		os.Exit(2)
	}

	output, err := RunSpeedtest(path, *sizeMB)
	if output != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// RunSpeedtest runs an in-tunnel latency, download, and upload test for the
// tunnel described by confPath and returns the human-readable report.
func RunSpeedtest(path string, sizeMB float64) (string, error) {
	if !strings.HasSuffix(path, ".conf") && !strings.Contains(path, "/") && !strings.Contains(path, "\\") {
		stdPath := filepath.Join("/etc/portbridge/tunnels", path+".conf")
		if _, err := os.Stat(stdPath); err == nil {
			path = stdPath
		} else {
			path = path + ".conf"
		}
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		return "", fmt.Errorf("config error: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return "", fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.LoadSecret(); err != nil {
		return "", fmt.Errorf("config %s: %w", path, err)
	}

	var buf strings.Builder

	// 1. If this server dials, dial the peer and run the speedtest directly
	if cfg.Dials() {
		routes := newRouter(cfg)
		fmt.Fprintf(&buf, "Connecting to %s (%s)...\n", cfg.Name, routes.describe())
		raw, claim, err := routes.dial(10 * time.Second)
		if err != nil {
			return buf.String(), fmt.Errorf("dial error: %w", err)
		}
		defer raw.Close()
		tuneSocket(raw)

		// Announce the purpose up front: a websocket link carries it in the
		// upgrade request, and a speed test announced as a tunnel never works.
		c, err := wrapDialPurpose(raw, cfg.withClaimedName(claim), authPurposeSpeedtest)
		if err != nil {
			return buf.String(), fmt.Errorf("securing link: %w", err)
		}
		defer c.Close()

		if err := sendAuthPurpose(c, cfg.secret, authPurposeSpeedtest); err != nil {
			return buf.String(), fmt.Errorf("auth error: %w", err)
		}

		if err := runSpeedtestClient(c, cfg, &buf, sizeMB); err != nil {
			return buf.String(), fmt.Errorf("speedtest error: %w", err)
		}
		return buf.String(), nil
	}

	// 2. If this server accepts, check if the running daemon can run a speedtest via control socket
	sockPath := cfg.ControlSocketPath()
	if c, err := net.DialTimeout("unix", sockPath, 2*time.Second); err == nil {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(120 * time.Second))
		if _, err := fmt.Fprintln(c, "speedtest"); err == nil {
			sc := bufio.NewScanner(c)
			for sc.Scan() {
				fmt.Fprintln(&buf, sc.Text())
			}
			out := buf.String()
			if !strings.Contains(out, "RTT:") {
				msg := strings.TrimSpace(out)
				if msg == "" {
					msg = "speedtest did not complete"
				}
				return out, fmt.Errorf("%s", msg)
			}
			return out, nil
		}
	}

	return "", fmt.Errorf("Tunnel %q is not running on this server, or cannot initiate a speedtest right now.", cfg.Name)
}
