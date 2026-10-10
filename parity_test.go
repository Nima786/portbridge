package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The menu writes settings files and pairing codes in shell, the engine reads
// them in Go, and nothing but convention kept the two in agreement. A setting
// the menu wrote under a name the engine did not know would stop a tunnel from
// starting; a field the menu put in a code and the engine ignored would be
// silently lost. These tests read the menu's own text and hold both to account.

func readMenu(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("scripts/portbridge-menu")
	if err != nil {
		t.Skipf("menu not available: %v", err)
	}
	return string(b)
}

// Every setting name the menu writes must be one the engine accepts.
func TestMenuOnlyWritesSettingsTheEngineKnows(t *testing.T) {
	menu := readMenu(t)

	keys := map[string]bool{}
	// printf 'key = %s\n' ... inside the settings writer
	for _, m := range regexp.MustCompile(`printf '(?:\\n)?([a-z_]+) = `).FindAllStringSubmatch(menu, -1) {
		keys[m[1]] = true
	}
	// write_conf "$name" key value
	for _, m := range regexp.MustCompile(`write_conf "\$[a-z_]+" ([a-z_]+) `).FindAllStringSubmatch(menu, -1) {
		keys[m[1]] = true
	}
	if len(keys) < 15 {
		t.Fatalf("only found %d settings in the menu; the pattern no longer matches it", len(keys))
	}

	// Settings the menu reads or writes for its own purposes, which the engine
	// is told about through other means or does not need.
	menuOnly := map[string]bool{"foreign_agent": false}

	for k := range keys {
		cfg := defaultConfig()
		err := cfg.set(k, "1")
		if err != nil && strings.Contains(err.Error(), "unknown setting") {
			if _, ok := menuOnly[k]; ok {
				continue
			}
			t.Errorf("the menu writes %q, which the engine does not know", k)
		}
	}
}

// The fields of a pairing code: what the menu writes and what the engine reads
// must be the same list.
func TestPairingCodeFieldsMatch(t *testing.T) {
	menu := readMenu(t)

	m := regexp.MustCompile(`printf 'v=6\\n([^']*)'`).FindStringSubmatch(menu)
	if m == nil {
		t.Fatalf("could not find the code format in the menu")
	}
	var menuKeys []string
	for _, part := range strings.Split(m[1], `\n`) {
		if k, _, ok := strings.Cut(part, "="); ok && k != "" {
			menuKeys = append(menuKeys, k)
		}
	}
	menuKeys = append(menuKeys, "v")

	engineKeys := []string{
		"v", "name", "mode", "tunnel_port", "relay_ip", "server_ip", "inbound_port", "pool",
		"transport", "server_name", "ws_path", "cdn", "alt_host", "mux", "mux_links",
		"utls", "tls_fragment", "clean_ips", "secret",
	}

	sort.Strings(menuKeys)
	sort.Strings(engineKeys)
	if strings.Join(menuKeys, ",") != strings.Join(engineKeys, ",") {
		t.Fatalf("the menu writes %v\nthe engine reads %v", menuKeys, engineKeys)
	}

	// Version 7 is the same with the web header of a plain link added.
	m7 := regexp.MustCompile(`printf 'v=7\\n([^']*)'`).FindStringSubmatch(menu)
	if m7 == nil {
		t.Fatalf("could not find the version 7 code format in the menu")
	}
	var keys7 []string
	for _, part := range strings.Split(m7[1], `\n`) {
		if k, _, ok := strings.Cut(part, "="); ok && k != "" {
			keys7 = append(keys7, k)
		}
	}
	keys7 = append(keys7, "v")
	want7 := append(append([]string{}, engineKeys...), "http_header", "http_host")
	sort.Strings(keys7)
	sort.Strings(want7)
	if strings.Join(keys7, ",") != strings.Join(want7, ",") {
		t.Fatalf("the menu's version 7 code has %v\nthe engine reads %v", keys7, want7)
	}

	// Version 8 is the same as 6 with the private GRE link added.
	m8 := regexp.MustCompile(`printf 'v=8\\n([^']*)'`).FindStringSubmatch(menu)
	if m8 == nil {
		t.Fatalf("could not find the version 8 code format in the menu")
	}
	var keys8 []string
	for _, part := range strings.Split(m8[1], `\n`) {
		if k, _, ok := strings.Cut(part, "="); ok && k != "" {
			keys8 = append(keys8, k)
		}
	}
	keys8 = append(keys8, "v")
	want8 := append(append([]string{}, engineKeys...), "gre")
	sort.Strings(keys8)
	sort.Strings(want8)
	if strings.Join(keys8, ",") != strings.Join(want8, ",") {
		t.Fatalf("the menu's version 8 code has %v\nthe engine reads %v", keys8, want8)
	}

	// Version 9 is the same as 6 with real_site added.
	m9 := regexp.MustCompile(`printf 'v=9\\n([^']*)'`).FindStringSubmatch(menu)
	if m9 == nil {
		t.Fatalf("could not find the version 9 code format in the menu")
	}
	var keys9 []string
	for _, part := range strings.Split(m9[1], `\n`) {
		if k, _, ok := strings.Cut(part, "="); ok && k != "" {
			keys9 = append(keys9, k)
		}
	}
	keys9 = append(keys9, "v")
	want9 := append(append([]string{}, engineKeys...), "real_site")
	sort.Strings(keys9)
	sort.Strings(want9)
	if strings.Join(keys9, ",") != strings.Join(want9, ",") {
		t.Fatalf("the menu's version 9 code has %v\nthe engine reads %v", keys9, want9)
	}
}
