package engine

import (
	"net"
	"testing"
	"time"
)

// A stranger sending junk must not be able to tell this server by how soon it
// gives up: almost all junk used to be dropped after exactly 19 bytes.
func TestJunkIsNotDroppedAfterTheFirstFewBytes(t *testing.T) {
	secret := []byte("a-test-secret-that-is-long-enough")
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	result := make(chan error, 1)
	go func() {
		_, err := recvAuthPurpose(srv, secret, nil)
		result <- err
	}()

	junk := make([]byte, 400)
	for i := range junk {
		junk[i] = byte(i*7 + 3)
	}
	junk[0] = 0x55 // neither protocol version

	// Enough bytes for the old early exit (19), and then some, but fewer than a
	// shortest real frame (19 + 16 + 32).
	if _, err := cli.Write(junk[:40]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("junk was given up on after 40 bytes: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// With the longest real frame's worth of bytes sent, it ends.
	go func() { _, _ = cli.Write(junk[40:130]) }()
	select {
	case err := <-result:
		if err != errAuthMAC {
			t.Fatalf("junk gave %v, want %v", err, errAuthMAC)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("junk was never given up on")
	}
}
