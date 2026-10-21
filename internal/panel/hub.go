package panel

// The panel's side of agents calling in (see internal/agent/callhome.go).
//
// An agent that calls holds a request open on /hub/poll. When the panel wants to
// ask that server something, it hands the waiting poll the request, and the agent
// posts the answer to /hub/reply. Each agent proves who it is with its own token.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

type hubCall struct {
	req     agent.HubRequest
	reply   chan agent.HubReply
	server  string      // the server this was meant for
	dropped atomic.Bool // the caller gave up; it must not be run later
}

type hub struct {
	mu       sync.Mutex
	queues   map[string]chan *hubCall // by server ID
	waiting  map[string]*hubCall      // by request ID
	lastPoll map[string]time.Time     // by server ID
	tokenFor func() map[string]string // server ID -> token, of servers that call in
}

func newHub(tokens func() map[string]string) *hub {
	return &hub{
		queues:   map[string]chan *hubCall{},
		waiting:  map[string]*hubCall{},
		lastPoll: map[string]time.Time{},
		tokenFor: tokens,
	}
}

func (h *hub) queue(id string) chan *hubCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	q := h.queues[id]
	if q == nil {
		q = make(chan *hubCall, 32)
		h.queues[id] = q
	}
	return q
}

// who works out which server a request comes from, by its token. Every token is
// compared, in constant time, so the time taken says nothing about any of them.
func (h *hub) who(r *http.Request) string {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return ""
	}
	found := ""
	for id, tok := range h.tokenFor() {
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			found = id
		}
	}
	return found
}

// connected says whether the server has polled recently.
func (h *hub) connected(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Since(h.lastPoll[id]) < agent.HubPollWait+15*time.Second
}

func (h *hub) handlePoll(w http.ResponseWriter, r *http.Request) {
	id := h.who(r)
	if id == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	h.mu.Lock()
	h.lastPoll[id] = time.Now()
	h.mu.Unlock()
	q := h.queue(id)
	timer := time.NewTimer(agent.HubPollWait)
	defer timer.Stop()
wait:
	for {
		select {
		case call := <-q:
			// The caller may have given up while this sat in the queue (the panel
			// said "did not answer in time"). Running it now would apply a change
			// the user was told had failed, possibly after they tried again.
			if call.dropped.Load() {
				continue
			}
			h.mu.Lock()
			h.waiting[call.req.ID] = call
			h.mu.Unlock()
			// A request can carry a whole release, which takes a while to send.
			if len(call.req.Body) > 1<<20 {
				agent.ExtendDeadlines(w, 15*time.Minute)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(call.req)
			break wait
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			break wait
		case <-r.Context().Done():
			break wait
		}
	}
	h.mu.Lock()
	h.lastPoll[id] = time.Now()
	h.mu.Unlock()
}

func (h *hub) handleReply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	from := h.who(r)
	if from == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	// An answer can carry a release a server downloaded for the panel.
	agent.ExtendDeadlines(w, 15*time.Minute)
	var rep agent.HubReply
	if err := json.NewDecoder(io.LimitReader(r.Body, agent.HubBodyLimit)).Decode(&rep); err != nil {
		http.Error(w, `{"error":"bad reply"}`, http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	call := h.waiting[rep.ID]
	// Only the server a request was sent to may answer it. Another server that
	// somehow learned its number must not be able to answer in its place.
	if call != nil && call.server == from {
		delete(h.waiting, rep.ID)
	} else {
		call = nil
	}
	h.mu.Unlock()
	if call != nil {
		select {
		case call.reply <- rep:
		default:
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

var errNotCalling = errors.New("the server is not calling the panel right now")

// do sends one request to a server that calls in, and waits for its answer.
func (h *hub) do(ctx context.Context, serverID, method, path string, body []byte) (int, []byte, error) {
	if !h.connected(serverID) {
		return 0, nil, errNotCalling
	}
	call := &hubCall{
		req:    agent.HubRequest{ID: newID(12), Method: method, Path: path, Body: body},
		reply:  make(chan agent.HubReply, 1),
		server: serverID,
	}
	select {
	case h.queue(serverID) <- call:
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
	select {
	case rep := <-call.reply:
		return rep.Status, rep.Body, nil
	case <-ctx.Done():
		// Whether it is still queued or already handed out, it is not wanted now.
		call.dropped.Store(true)
		h.mu.Lock()
		delete(h.waiting, call.req.ID)
		h.mu.Unlock()
		return 0, nil, errors.New("the server did not answer in time")
	}
}
