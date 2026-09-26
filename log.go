package main

import (
	"log"
	"sync/atomic"
	"time"
)

const logThrottleWindow = 5 * time.Second

// throttled emits at most one message per window. A tunnel that is failing can
// fail thousands of times a second, and an unthrottled log line in that path
// will fill a disk.
type throttled struct {
	gate   uint32
	window time.Duration
}

func newThrottled() *throttled {
	return &throttled{window: logThrottleWindow}
}

func (t *throttled) printf(format string, args ...interface{}) {
	if !atomic.CompareAndSwapUint32(&t.gate, 0, 1) {
		return
	}
	log.Printf(format, args...)
	go func() {
		time.Sleep(t.window)
		atomic.StoreUint32(&t.gate, 0)
	}()
}
