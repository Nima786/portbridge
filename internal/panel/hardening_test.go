package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

// Attempts sent all at once must not get more guesses than the same attempts
// sent one after another.
func TestLoginBurstCannotOutrunTheLock(t *testing.T) {
	s := newSessions()
	var allowed int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.admit("203.0.113.9"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
				// still being checked when the rest arrive
				time.Sleep(20 * time.Millisecond)
				s.finish("203.0.113.9", false)
			}
		}()
	}
	wg.Wait()
	if allowed > lockAfter {
		t.Fatalf("%d guesses got through a burst; the limit is %d", allowed, lockAfter)
	}
}

func TestAnIPv6AddressCountsAsItsWholeSlash64(t *testing.T) {
	get := func(addr string) string {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		r.RemoteAddr = addr
		return clientIP(r)
	}
	a := get("[2001:db8:1:2:aaaa::1]:5000")
	b := get("[2001:db8:1:2:bbbb::9]:6000")
	c := get("[2001:db8:1:3::1]:5000")
	if a != b {
		t.Errorf("two addresses in one /64 counted separately: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("addresses in different /64s were counted together: %q", a)
	}
	if got := get("198.51.100.7:1234"); got != "198.51.100.7" {
		t.Errorf("an IPv4 address changed: %q", got)
	}
}

// A request the panel gave up on must not be carried out when the server next
// calls in.
func TestHubDoesNotRunARequestTheCallerGaveUpOn(t *testing.T) {
	h := newHub(func() map[string]string { return map[string]string{"srv": "tok", "other": "tok2"} })
	h.mu.Lock()
	h.lastPoll["srv"] = time.Now()
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := h.do(ctx, "srv", http.MethodPost, "/api/tunnel/delete", []byte(`{}`)); err == nil {
		t.Fatal("do should have timed out")
	}

	// The server calls in afterwards: it must get nothing for that request.
	req := httptest.NewRequest(http.MethodGet, "/hub/poll", nil)
	req.Header.Set("Authorization", "Bearer tok")
	pollCtx, pollCancel := context.WithTimeout(req.Context(), 300*time.Millisecond)
	defer pollCancel()
	rec := httptest.NewRecorder()
	h.handlePoll(rec, req.WithContext(pollCtx))
	if rec.Body.Len() != 0 {
		t.Fatalf("a request the panel gave up on was handed to the server: %s", rec.Body.String())
	}
}

// Only the server a request was sent to may answer it.
func TestHubAcceptsAnswersOnlyFromTheServerAsked(t *testing.T) {
	h := newHub(func() map[string]string { return map[string]string{"srv": "tok", "other": "tok2"} })
	h.mu.Lock()
	h.lastPoll["srv"] = time.Now()
	h.mu.Unlock()

	done := make(chan int, 1)
	go func() {
		st, _, _ := h.do(context.Background(), "srv", http.MethodGet, "/api/overview", nil)
		done <- st
	}()
	// srv picks the request up.
	var id string
	deadline := time.Now().Add(2 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/hub/poll", nil)
		req.Header.Set("Authorization", "Bearer tok")
		ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
		rec := httptest.NewRecorder()
		h.handlePoll(rec, req.WithContext(ctx))
		cancel()
		h.mu.Lock()
		for k := range h.waiting {
			id = k
		}
		h.mu.Unlock()
	}
	if id == "" {
		t.Fatal("the request was never handed out")
	}
	reply := func(token string, status int) {
		body := fmt.Sprintf(`{"id":%q,"status":%d}`, id, status)
		r := httptest.NewRequest(http.MethodPost, "/hub/reply", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		h.handleReply(httptest.NewRecorder(), r)
	}
	reply("tok2", 111) // the wrong server
	select {
	case st := <-done:
		t.Fatalf("another server's answer (%d) was accepted", st)
	case <-time.After(200 * time.Millisecond):
	}
	reply("tok", 222) // the right one
	select {
	case st := <-done:
		if st != 222 {
			t.Fatalf("answer %d", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the right server's answer was not accepted")
	}
}

var _ = agent.HubPollWait
