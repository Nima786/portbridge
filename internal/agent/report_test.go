package agent

import "testing"

func TestParseProcStatCPU(t *testing.T) {
	raw := "cpu  1200 50 350 8000 400 0 0 0 0 0\ncpu0 600 25 175 4000 200 0 0 0 0 0\n"
	total, idle, ok := parseProcStatCPU(raw)
	if !ok {
		t.Fatal("expected parseProcStatCPU to succeed")
	}
	if total != 10000 {
		t.Fatalf("total = %d, want 10000", total)
	}
	if idle != 8400 {
		t.Fatalf("idle = %d, want 8400 (idle + iowait)", idle)
	}
}

func TestParseProcMeminfo(t *testing.T) {
	raw := `MemTotal:        4096000 kB
MemFree:          512000 kB
MemAvailable:    2048000 kB
Buffers:          256000 kB
Cached:          1280000 kB
`
	total, avail, pct, ok := parseProcMeminfo(raw)
	if !ok {
		t.Fatal("expected parseProcMeminfo to succeed")
	}
	if total != 4096000*1024 {
		t.Fatalf("total = %d, want %d", total, 4096000*1024)
	}
	if avail != 2048000*1024 {
		t.Fatalf("avail = %d, want %d", avail, 2048000*1024)
	}
	if pct != 50.0 {
		t.Fatalf("pct = %v, want 50.0", pct)
	}
}
