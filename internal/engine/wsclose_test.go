package engine

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"
)

// A shared link over websocket used to read the same buffered reader from two
// goroutines when it was torn down: one still in Read, one in Close draining the
// tail. That can panic and take the whole process down. This hammers that exact
// race so `go test -race` would catch a regression.
func TestWSConnCloseDoesNotRaceRead(t *testing.T) {
	for i := 0; i < 50; i++ {
		c1, c2 := net.Pipe()
		w := &wsConn{Conn: c1, br: bufio.NewReader(c1)}

		var wg sync.WaitGroup
		wg.Add(2)
		// A reader, like the mux readLoop.
		go func() {
			defer wg.Done()
			buf := make([]byte, 64)
			for {
				if _, err := w.Read(buf); err != nil {
					return
				}
			}
		}()
		// The other end dribbles a little so the reader is mid-frame.
		go func() {
			_, _ = c2.Write([]byte{0x82, 0x02, 'h', 'i'})
		}()
		// Close while the reader is active, as carrier.fail does.
		go func() {
			defer wg.Done()
			time.Sleep(time.Millisecond)
			_ = w.Close()
		}()
		wg.Wait()
		_ = c2.Close()
	}
}
