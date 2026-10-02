package main

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
	log.Printf("[speedtest-server] handling connection from %s", c.RemoteAddr())

	buf := make([]byte, 32*1024)
	_, _ = rand.Read(buf[:256])
	for i := 256; i < len(buf); i++ {
		buf[i] = buf[i%256] ^ byte(i)
	}

	for {
		var phase [1]byte
		if _, err := io.ReadFull(c, phase[:]); err != nil {
			log.Printf("[speedtest-server] read phase err from %s: %v", c.RemoteAddr(), err)
			return
		}
		log.Printf("[speedtest-server] phase 0x%02x from %s", phase[0], c.RemoteAddr())

		switch phase[0] {
		case 0x01: // Latency / Ping phase
			const numSamples = 1
			for i := 0; i < numSamples; i++ {
				var ts [8]byte
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.ReadFull(c, ts[:]); err != nil {
					log.Printf("[speedtest-server] ping sample %d read err: %v", i, err)
					return
				}
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(ts[:]); err != nil {
					log.Printf("[speedtest-server] ping sample %d write err: %v", i, err)
					return
				}
				log.Printf("[speedtest-server] ping sample %d echoed successfully", i)
			}
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			log.Printf("[speedtest-server] ping phase completed")

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


	// Phase 2: Download Test
	mb := 1.0
	if len(sizeMB) > 0 && sizeMB[0] > 0 {
		mb = sizeMB[0]
	}
	testSize := uint32(mb * 1024 * 1024)
	if testSize == 0 {
		testSize = 1024 * 1024
	}
	fmt.Fprintf(out, "⬇️  Testing download throughput (%.2f MB)...\n", float64(testSize)/(1024*1024))
	dlHeader := make([]byte, 5)
	dlHeader[0] = 0x02
	binary.BigEndian.PutUint32(dlHeader[1:], testSize)
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
	if _, err := c.Write(dlHeader); err != nil {
		return fmt.Errorf("download phase start: %w", err)
	}

	var dlReady [1]byte
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(c, dlReady[:]); err != nil {
		return fmt.Errorf("download ready ACK: %w", err)
	}

	dlStart := time.Now()
	readBuf := make([]byte, 32*1024)
	var dlRead int64
	var dlErr error
	for dlRead < int64(testSize) {
		toRead := int64(len(readBuf))
		if rem := int64(testSize) - dlRead; rem < toRead {
			toRead = rem
		}
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := c.Read(readBuf[:toRead])
		if n > 0 {
			dlRead += int64(n)
		}
		if err != nil {
			dlErr = err
			break
		}
	}
	dlElapsed := time.Since(dlStart)
	if dlRead == 0 && dlErr != nil {
		return fmt.Errorf("download reading: %w", dlErr)
	}
	dlMBps := (float64(dlRead) / (1024 * 1024)) / dlElapsed.Seconds()
	dlMbps := (float64(dlRead) * 8 / 1_000_000) / dlElapsed.Seconds()

	if dlErr != nil {
		fmt.Fprintf(out, "   Download: %.2f MB/s (%.1f Mbps) (partial: %d/%d bytes in %.2fs: %v)\n\n", dlMBps, dlMbps, dlRead, testSize, dlElapsed.Seconds(), dlErr)
	} else {
		fmt.Fprintf(out, "   Download: %.2f MB/s (%.1f Mbps) in %.2fs\n\n", dlMBps, dlMbps, dlElapsed.Seconds())
	}

	// Phase 3: Upload Test
	fmt.Fprintf(out, "⬆️  Testing upload throughput (%.2f MB)...\n", float64(testSize)/(1024*1024))
	ulHeader := make([]byte, 5)
	ulHeader[0] = 0x03
	binary.BigEndian.PutUint32(ulHeader[1:], testSize)
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
	if _, err := c.Write(ulHeader); err != nil {
		return fmt.Errorf("upload phase start: %w", err)
	}

	var ulReady [1]byte
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(c, ulReady[:]); err != nil {
		return fmt.Errorf("upload ready ACK: %w", err)
	}

	sendChunk := make([]byte, 32*1024)
	_, _ = rand.Read(sendChunk[:128])
	for i := 128; i < len(sendChunk); i++ {
		sendChunk[i] = sendChunk[i%128] ^ byte(i)
	}

	ulStart := time.Now()
	var ulSent int64
	var ulErr error
	for ulSent < int64(testSize) {
		toWrite := int64(len(sendChunk))
		if rem := int64(testSize) - ulSent; rem < toWrite {
			toWrite = rem
		}
		_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
		n, err := c.Write(sendChunk[:toWrite])
		if n > 0 {
			ulSent += int64(n)
		}
		if err != nil {
			ulErr = err
			break
		}
	}

	var ulAck [1]byte
	if ulErr == nil {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(c, ulAck[:]); err != nil {
			ulErr = err
		}
	}
	ulElapsed := time.Since(ulStart)
	if ulSent == 0 && ulErr != nil {
		return fmt.Errorf("upload writing: %w", ulErr)
	}
	ulMBps := (float64(ulSent) / (1024 * 1024)) / ulElapsed.Seconds()
	ulMbps := (float64(ulSent) * 8 / 1_000_000) / ulElapsed.Seconds()

	if ulErr != nil {
		fmt.Fprintf(out, "   Upload: %.2f MB/s (%.1f Mbps) (partial: %d/%d bytes in %.2fs: %v)\n\n", ulMBps, ulMbps, ulSent, testSize, ulElapsed.Seconds(), ulErr)
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

func cmdSpeedtest(args []string) {
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

	// If given a short tunnel name (e.g. ir-nl), locate its file in /etc/portbridge/tunnels/
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
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", path, err)
		os.Exit(1)
	}
	if err := cfg.LoadSecret(); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", path, err)
		os.Exit(1)
	}

	// 1. If this server dials, dial the peer and run the speedtest directly
	if cfg.Dials() {
		routes := newRouter(cfg)
		fmt.Printf("Connecting to %s (%s)...\n", cfg.Name, routes.describe())
		raw, claim, err := routes.dial(10 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial error: %v\n", err)
			os.Exit(1)
		}
		defer raw.Close()
		tuneSocket(raw)

		c, err := wrapDial(raw, cfg.withClaimedName(claim))
		if err != nil {
			fmt.Fprintf(os.Stderr, "securing link: %v\n", err)
			os.Exit(1)
		}
		defer c.Close()

		if err := sendAuthPurpose(c, cfg.secret, authPurposeSpeedtest); err != nil {
			fmt.Fprintf(os.Stderr, "auth error: %v\n", err)
			os.Exit(1)
		}

		if err := runSpeedtestClient(c, cfg, os.Stdout, *sizeMB); err != nil {
			fmt.Fprintf(os.Stderr, "speedtest error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 2. If this server accepts, check if the running daemon can run a speedtest via control socket
	sockPath := cfg.ControlSocketPath()
	if c, err := net.DialTimeout("unix", sockPath, 2*time.Second); err == nil {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
		if _, err := fmt.Fprintln(c, "speedtest"); err == nil {
			sc := bufio.NewScanner(c)
			for sc.Scan() {
				fmt.Println(sc.Text())
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Tunnel %q waits for incoming connections on this server.\nPlease run 'portbridge speedtest %s' on the other server (%s).\n",
		cfg.Name, cfg.Name, cfg.PeerIP)
	os.Exit(1)
}
