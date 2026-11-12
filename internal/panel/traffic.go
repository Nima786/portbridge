package panel

// Live throughput, persistent cumulative bandwidth accounting, and monthly
// traffic quotas per tunnel.
//
// Each running tunnel writes cumulative bytes_up / bytes_down and smoothed
// up_bps / down_bps to its status.json, keyed by process PID and start time.
// trafficTracker computes monotonic deltas across process restarts, transport
// mode switches, and panel restarts so bandwidth totals are never lost or
// double-counted, enforces optional monthly GB caps (80% alert, 100% alert +
// optional auto-pause), and automatically resumes quota-paused tunnels when a
// new UTC calendar month begins.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	bytesPerGB           = 1024.0 * 1024.0 * 1024.0
	trafficTickInterval  = 15 * time.Second
	trafficFlushInterval = 30 * time.Second
)

// TunnelTrafficView is attached to each tunnelView returned by GET /api/tunnels.
type TunnelTrafficView struct {
	UpBps         int64   `json:"up_bps"`
	DownBps       int64   `json:"down_bps"`
	TotalUp       int64   `json:"total_up"`
	TotalDown     int64   `json:"total_down"`
	MonthKey      string  `json:"month_key"`
	MonthUp       int64   `json:"month_up"`
	MonthDown     int64   `json:"month_down"`
	QuotaGB       float64 `json:"quota_gb,omitempty"`
	AutoPause     bool    `json:"auto_pause,omitempty"`
	PausedByQuota bool    `json:"paused_by_quota,omitempty"`
}

type tunnelTrafficRequest struct {
	Name      string  `json:"name"`
	Edge      string  `json:"edge"`
	Origin    string  `json:"origin"`
	Action    string  `json:"action"` // "set_quota" (default) or "reset"
	QuotaGB   float64 `json:"quota_gb"`
	AutoPause bool    `json:"auto_pause"`
	Scope     string  `json:"scope,omitempty"` // "all" (default) or "month"
}

type trafficTracker struct {
	p *Panel

	mu        sync.Mutex
	byKey     map[string]TunnelTraffic
	dirty     bool
	lastFlush time.Time
	nowFn     func() time.Time
}

func newTrafficTracker(p *Panel) *trafficTracker {
	tt := &trafficTracker{
		p:     p,
		byKey: map[string]TunnelTraffic{},
		nowFn: time.Now,
	}
	tt.reloadFromStore()
	return tt
}

func (tt *trafficTracker) now() time.Time {
	if tt.nowFn != nil {
		return tt.nowFn()
	}
	return time.Now()
}

func (tt *trafficTracker) reloadFromStore() {
	st := tt.p.store.get()
	tt.mu.Lock()
	tt.byKey = make(map[string]TunnelTraffic, len(st.Traffic))
	for k, v := range st.Traffic {
		tt.byKey[k] = v
	}
	tt.dirty = false
	tt.lastFlush = tt.now()
	tt.mu.Unlock()
}

func trafficKeyForTarget(edgeID, originID, name string) string {
	if edgeID != "" {
		return healKeyFor(edgeID, name)
	}
	if originID != "" {
		return "origin:" + originID + "/" + name
	}
	return name
}

func trafficKeyForView(tv tunnelView) string {
	var edgeID, originID string
	if tv.Edge != nil {
		edgeID = tv.Edge.ServerID
	}
	if tv.Origin != nil {
		originID = tv.Origin.ServerID
	}
	return trafficKeyForTarget(edgeID, originID, tv.Name)
}

func (tt *trafficTracker) run(ctx context.Context) {
	ticker := time.NewTicker(trafficTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			tt.flushNow()
			return
		case <-ticker.C:
			views := tt.p.fleet.views()
			if tt.p.notifier != nil {
				tt.p.notifier.observeServers(views)
			}
			tunnels := pairTunnels(views)
			tt.observeAndAttach(tunnels)
		}
	}
}

type pendingQuotaAction struct {
	target tunnelTarget
	action string // "start" or "stop"
}

type pendingQuotaAlert struct {
	name    string
	pct     int
	usedGB  float64
	quotaGB float64
	paused  bool
}

// observeAndAttach updates monotonic counters from the latest tunnel views,
// triggers monthly rollover / quota enforcement, and populates tv.Traffic.
func (tt *trafficTracker) observeAndAttach(tunnels []tunnelView) {
	now := tt.now().UTC()
	curMonth := now.Format("2006-01")
	nowISO := now.Format(time.RFC3339)

	var actions []pendingQuotaAction
	var alerts []pendingQuotaAlert
	urgentFlush := false

	tt.mu.Lock()
	for i := range tunnels {
		tv := &tunnels[i]
		key := trafficKeyForView(*tv)
		rec := tt.byKey[key]

		var edgeID, originID string
		if tv.Edge != nil {
			edgeID = tv.Edge.ServerID
		}
		if tv.Origin != nil {
			originID = tv.Origin.ServerID
		}
		target := tunnelTarget{Name: tv.Name, Edge: edgeID, Origin: originID}

		// 1. Handle calendar month initialization or rollover.
		if rec.MonthKey == "" {
			rec.MonthKey = curMonth
		} else if rec.MonthKey != curMonth {
			rec.MonthKey = curMonth
			rec.MonthUp = 0
			rec.MonthDown = 0
			rec.Warned80Month = ""
			rec.ExceededMonth = ""
			if rec.PausedByQuota {
				rec.PausedByQuota = false
				actions = append(actions, pendingQuotaAction{target: target, action: "start"})
			}
			tt.dirty = true
			urgentFlush = true
		}

		// 2. Sample authoritative half (Edge for paired tunnels, Origin only if unpaired)
		// so Edge + Origin never double-count the same stream.
		var counterHalf *half
		if tv.Edge != nil {
			counterHalf = tv.Edge
		} else if tv.Origin != nil {
			counterHalf = tv.Origin
		}

		if counterHalf != nil && counterHalf.Info.Live != nil {
			live := counterHalf.Info.Live
			if live.PID > 0 || live.BytesUp > 0 || live.BytesDown > 0 {
				inst := fmt.Sprintf("%s:%d:%s", counterHalf.ServerID, live.PID, live.StartedAt)
				var dUp, dDown int64
				if rec.LastInstance == inst {
					if live.BytesUp > rec.LastRawUp {
						dUp = live.BytesUp - rec.LastRawUp
					}
					if live.BytesDown > rec.LastRawDown {
						dDown = live.BytesDown - rec.LastRawDown
					}
				} else {
					if live.BytesUp > 0 {
						dUp = live.BytesUp
					}
					if live.BytesDown > 0 {
						dDown = live.BytesDown
					}
					rec.LastInstance = inst
				}
				if rec.LastRawUp != live.BytesUp || rec.LastRawDown != live.BytesDown {
					rec.LastRawUp = live.BytesUp
					rec.LastRawDown = live.BytesDown
					tt.dirty = true
				}
				if dUp > 0 || dDown > 0 {
					rec.TotalUp += dUp
					rec.TotalDown += dDown
					rec.MonthUp += dUp
					rec.MonthDown += dDown
					rec.UpdatedAt = nowISO
					tt.dirty = true
				}
			}
		}

		// 3. Enforce monthly quota warnings (80%) and caps (100%).
		if rec.QuotaGB > 0 {
			quotaBytes := int64(math.Round(rec.QuotaGB * bytesPerGB))
			monthUsed := rec.MonthUp + rec.MonthDown
			usedGB := float64(monthUsed) / bytesPerGB
			if quotaBytes > 0 && monthUsed >= quotaBytes {
				if rec.ExceededMonth != curMonth {
					rec.ExceededMonth = curMonth
					rec.Warned80Month = curMonth
					paused := false
					if rec.AutoPause {
						rec.PausedByQuota = true
						paused = true
						actions = append(actions, pendingQuotaAction{target: target, action: "stop"})
					}
					alerts = append(alerts, pendingQuotaAlert{
						name:    tv.Name,
						pct:     100,
						usedGB:  usedGB,
						quotaGB: rec.QuotaGB,
						paused:  paused,
					})
					tt.dirty = true
					urgentFlush = true
				}
			} else if quotaBytes > 0 && float64(monthUsed) >= 0.80*float64(quotaBytes) {
				if rec.Warned80Month != curMonth {
					rec.Warned80Month = curMonth
					alerts = append(alerts, pendingQuotaAlert{
						name:    tv.Name,
						pct:     80,
						usedGB:  usedGB,
						quotaGB: rec.QuotaGB,
						paused:  false,
					})
					tt.dirty = true
					urgentFlush = true
				}
			}
		}

		tt.byKey[key] = rec

		// 4. Compute live throughput rates (0 when stopped or stale).
		var upBps, downBps int64
		if !tv.Stale {
			if tv.Edge != nil && tv.Edge.Info.Running && tv.Edge.Info.Live != nil {
				upBps = tv.Edge.Info.Live.UpBps
				downBps = tv.Edge.Info.Live.DownBps
			} else if tv.Origin != nil && tv.Origin.Info.Running && tv.Origin.Info.Live != nil {
				upBps = tv.Origin.Info.Live.UpBps
				downBps = tv.Origin.Info.Live.DownBps
			}
		}

		tv.Traffic = &TunnelTrafficView{
			UpBps:         upBps,
			DownBps:       downBps,
			TotalUp:       rec.TotalUp,
			TotalDown:     rec.TotalDown,
			MonthKey:      rec.MonthKey,
			MonthUp:       rec.MonthUp,
			MonthDown:     rec.MonthDown,
			QuotaGB:       rec.QuotaGB,
			AutoPause:     rec.AutoPause,
			PausedByQuota: rec.PausedByQuota,
		}
	}

	shouldFlush := urgentFlush || (tt.dirty && tt.now().Sub(tt.lastFlush) >= trafficFlushInterval)
	var snapshot map[string]TunnelTraffic
	if shouldFlush {
		snapshot = tt.snapshotLocked()
		tt.dirty = false
		tt.lastFlush = tt.now()
	}
	tt.mu.Unlock()

	if snapshot != nil {
		tt.persistSnapshot(snapshot)
	}
	for _, al := range alerts {
		if tt.p.notifier != nil {
			tt.p.notifier.notifyQuota(al.name, al.pct, al.usedGB, al.quotaGB, al.paused)
		}
	}
	for _, act := range actions {
		a := act
		go func() {
			logf("[traffic] %s tunnel %q due to monthly quota rule", a.action, a.target.Name)
			tt.p.serviceTunnel(a.target, a.action)
		}()
	}
}

func (tt *trafficTracker) snapshotLocked() map[string]TunnelTraffic {
	out := make(map[string]TunnelTraffic, len(tt.byKey))
	for k, v := range tt.byKey {
		if v.TotalUp == 0 && v.TotalDown == 0 && v.MonthUp == 0 && v.MonthDown == 0 &&
			v.QuotaGB == 0 && !v.AutoPause && !v.PausedByQuota && v.LastInstance == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func (tt *trafficTracker) persistSnapshot(snap map[string]TunnelTraffic) {
	_ = tt.p.store.update(func(st *State) error {
		st.Traffic = snap
		return nil
	})
}

func (tt *trafficTracker) flushNow() {
	tt.mu.Lock()
	if !tt.dirty {
		tt.mu.Unlock()
		return
	}
	snap := tt.snapshotLocked()
	tt.dirty = false
	tt.lastFlush = tt.now()
	tt.mu.Unlock()
	tt.persistSnapshot(snap)
}

func (tt *trafficTracker) forget(edgeID, name string) {
	key := healKeyFor(edgeID, name)
	tt.mu.Lock()
	delete(tt.byKey, key)
	snap := tt.snapshotLocked()
	tt.dirty = false
	tt.lastFlush = tt.now()
	tt.mu.Unlock()
	tt.persistSnapshot(snap)
}

func (tt *trafficTracker) clearPausedByQuota(edgeID, originID, name string) {
	key := trafficKeyForTarget(edgeID, originID, name)
	tt.mu.Lock()
	rec, ok := tt.byKey[key]
	if !ok || !rec.PausedByQuota {
		tt.mu.Unlock()
		return
	}
	rec.PausedByQuota = false
	tt.byKey[key] = rec
	snap := tt.snapshotLocked()
	tt.dirty = false
	tt.lastFlush = tt.now()
	tt.mu.Unlock()
	tt.persistSnapshot(snap)
}

func (tt *trafficTracker) applyRequest(req tunnelTrafficRequest) (TunnelTrafficView, error) {
	target := tunnelTarget{
		Name:   strings.TrimSpace(req.Name),
		Edge:   strings.TrimSpace(req.Edge),
		Origin: strings.TrimSpace(req.Origin),
	}
	if err := tt.p.knownTarget(target); err != nil {
		return TunnelTrafficView{}, err
	}
	action := strings.TrimSpace(strings.ToLower(req.Action))
	if action == "" {
		action = "set_quota"
	}
	if action != "set_quota" && action != "reset" {
		return TunnelTrafficView{}, errors.New("the action must be set_quota or reset")
	}
	if action == "set_quota" {
		if math.IsNaN(req.QuotaGB) || math.IsInf(req.QuotaGB, 0) || req.QuotaGB < 0 || req.QuotaGB > 1_000_000 {
			return TunnelTrafficView{}, errors.New("monthly quota must be between 0 (unlimited) and 1,000,000 GB")
		}
	}

	// Capture latest raw counters from live views first so reset baselines cleanly.
	tunnels := pairTunnels(tt.p.fleet.views())
	tt.observeAndAttach(tunnels)

	key := trafficKeyForTarget(target.Edge, target.Origin, target.Name)
	curMonth := tt.now().UTC().Format("2006-01")
	var serviceAct string

	tt.mu.Lock()
	rec := tt.byKey[key]
	if rec.MonthKey == "" {
		rec.MonthKey = curMonth
	}
	if action == "reset" {
		if strings.EqualFold(req.Scope, "month") {
			rec.MonthUp = 0
			rec.MonthDown = 0
		} else {
			rec.TotalUp = 0
			rec.TotalDown = 0
			rec.MonthUp = 0
			rec.MonthDown = 0
		}
		rec.Warned80Month = ""
		rec.ExceededMonth = ""
		if rec.PausedByQuota {
			rec.PausedByQuota = false
			serviceAct = "start"
		}
	} else {
		rec.QuotaGB = math.Round(req.QuotaGB*100) / 100
		rec.AutoPause = req.AutoPause
		monthUsed := rec.MonthUp + rec.MonthDown
		quotaBytes := int64(math.Round(rec.QuotaGB * bytesPerGB))
		if rec.QuotaGB <= 0 || monthUsed < quotaBytes {
			rec.ExceededMonth = ""
			if rec.QuotaGB <= 0 || float64(monthUsed) < 0.80*float64(quotaBytes) {
				rec.Warned80Month = ""
			}
			if rec.PausedByQuota {
				rec.PausedByQuota = false
				serviceAct = "start"
			}
		} else if !rec.AutoPause && rec.PausedByQuota {
			rec.PausedByQuota = false
			serviceAct = "start"
		} else if rec.QuotaGB > 0 && rec.AutoPause && monthUsed >= quotaBytes && !rec.PausedByQuota {
			rec.PausedByQuota = true
			rec.ExceededMonth = curMonth
			rec.Warned80Month = curMonth
			serviceAct = "stop"
		}
	}
	rec.UpdatedAt = tt.now().UTC().Format(time.RFC3339)
	tt.byKey[key] = rec
	snap := tt.snapshotLocked()
	tt.dirty = false
	tt.lastFlush = tt.now()
	view := TunnelTrafficView{
		TotalUp:       rec.TotalUp,
		TotalDown:     rec.TotalDown,
		MonthKey:      rec.MonthKey,
		MonthUp:       rec.MonthUp,
		MonthDown:     rec.MonthDown,
		QuotaGB:       rec.QuotaGB,
		AutoPause:     rec.AutoPause,
		PausedByQuota: rec.PausedByQuota,
	}
	tt.mu.Unlock()

	tt.persistSnapshot(snap)
	if serviceAct != "" {
		go tt.p.serviceTunnel(target, serviceAct)
	}
	return view, nil
}
