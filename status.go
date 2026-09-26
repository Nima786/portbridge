package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// status is the live picture the menu script reads. It is a file rather than a
// port so that nothing extra is listening on the network.
type status struct {
	cfg     *Config
	started time.Time
	pool    *pool

	activeSessions   int64
	failedSessions   int64
	droppedSessions  int64
	parkedSpares     int64
	retries          int64
	emptyConnections int64
}

type statusFile struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	Role            string `json:"role"`
	Dials           bool   `json:"dials_out"`
	TunnelAddr      string `json:"tunnel_addr"`
	UserListen      string `json:"user_listen,omitempty"`
	InboundAddr     string `json:"inbound_addr,omitempty"`
	PID             int    `json:"pid"`
	StartedAt       string `json:"started_at"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	ActiveSessions  int64  `json:"active_sessions"`
	ParkedSpares    int64  `json:"parked_spares"`
	PoolTarget      int    `json:"pool_target"`
	FailedSessions  int64  `json:"failed_sessions"`
	DroppedSessions int64  `json:"dropped_sessions"`
	Retries         int64  `json:"retries"`
	// EmptyConnections counts connections that arrived and left without sending
	// anything, which is mostly internet background scanning.
	EmptyConnections int64  `json:"empty_connections"`
	UpdatedAt        string `json:"updated_at"`
}

func newStatus(cfg *Config) *status {
	return &status{cfg: cfg, started: time.Now()}
}

// publish writes the status file every few seconds until the context ends, then
// removes it so a stopped tunnel does not look alive.
func (s *status) publish(ctx context.Context) {
	if s.cfg.StatusFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.StatusFile), 0o755); err != nil {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	s.writeOnce()
	for {
		select {
		case <-ctx.Done():
			_ = os.Remove(s.cfg.StatusFile)
			return
		case <-ticker.C:
			s.writeOnce()
		}
	}
}

func (s *status) writeOnce() {
	parked := atomic.LoadInt64(&s.parkedSpares)
	// On the edge the pool itself is the authority on how many are ready.
	if s.pool != nil {
		parked = int64(s.pool.parkedCount())
	}

	sf := statusFile{
		Name:             s.cfg.Name,
		Mode:             string(s.cfg.Mode),
		Role:             string(s.cfg.Role),
		Dials:            s.cfg.Dials(),
		TunnelAddr:       s.cfg.TunnelAddr,
		UserListen:       s.cfg.UserListen,
		InboundAddr:      s.cfg.InboundAddr,
		PID:              os.Getpid(),
		StartedAt:        s.started.UTC().Format(time.RFC3339),
		UptimeSeconds:    int64(time.Since(s.started).Seconds()),
		ActiveSessions:   atomic.LoadInt64(&s.activeSessions),
		ParkedSpares:     parked,
		PoolTarget:       s.cfg.PoolSize,
		FailedSessions:   atomic.LoadInt64(&s.failedSessions),
		DroppedSessions:  atomic.LoadInt64(&s.droppedSessions),
		Retries:          atomic.LoadInt64(&s.retries),
		EmptyConnections: atomic.LoadInt64(&s.emptyConnections),
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return
	}
	// Write to a temporary file and rename, so a reader never sees half a file.
	tmp := s.cfg.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, s.cfg.StatusFile)
}
