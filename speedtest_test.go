package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestSpeedtestLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		runSpeedtestServer(c)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	cfg := &Config{
		Name:       "loopback",
		Mode:       ModeDirect,
		Role:       RoleEdge,
		TunnelAddr: ln.Addr().String(),
		Transport:  TransportPlain,
	}

	var buf bytes.Buffer
	if err := runSpeedtestClient(clientConn, cfg, &buf); err != nil {
		t.Fatalf("runSpeedtestClient failed: %v", err)
	}

	out := buf.String()
	t.Logf("Speedtest output:\n%s", out)

	if !strings.Contains(out, "PortBridge Speed Test") {
		t.Errorf("missing header in output: %s", out)
	}
	if !strings.Contains(out, "Download:") {
		t.Errorf("missing download result in output: %s", out)
	}
	if !strings.Contains(out, "Upload:") {
		t.Errorf("missing upload result in output: %s", out)
	}
}

func TestSpeedtestKCP(t *testing.T) {
	cfg := &Config{
		Name:            "kcp-test",
		Mode:            ModeDirect,
		Role:            RoleEdge,
		Transport:       TransportKCP,
		KCPDataShards:   10,
		KCPParityShards: 3,
		secret:          []byte("testsecret123456"),
	}

	ln, err := kcpListen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("kcpListen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		runSpeedtestServer(c)
	}()

	clientConn, err := kcpDial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("kcpDial: %v", err)
	}
	defer clientConn.Close()

	cfg.TunnelAddr = ln.Addr().String()

	var buf bytes.Buffer
	if err := runSpeedtestClient(clientConn, cfg, &buf); err != nil {
		t.Fatalf("runSpeedtestClient failed: %v", err)
	}

	out := buf.String()
	t.Logf("KCP Speedtest output:\n%s", out)
}
