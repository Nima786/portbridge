package engine

import (
	"net"
	"testing"
)

// Asking for a bigger buffer than the system allows must never break a socket,
// whether or not the program may go past the limit.
func TestGrowSocketBuffersIsHarmless(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	growSocketBuffers(pc, 8*1024*1024)
	growSocketBuffers("not a socket", 8*1024*1024)
	growSocketBuffers(nil, 8*1024*1024)

	// Still usable afterwards.
	c, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, _, err := pc.ReadFrom(buf); err != nil || n != 1 {
		t.Fatalf("socket broken after growing its buffers: %d %v", n, err)
	}
}
