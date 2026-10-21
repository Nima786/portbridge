package agent

import (
	"strings"
	"testing"
)

func TestLiteSpeedTrustedLoopbackIsAddedAndRemoved(t *testing.T) {
	cfg := "<a><virtualHost><accessControl><allow>10.0.0.0/8</allow></accessControl></virtualHost>" +
		"<security><accessControl>\n<allow>\nALL\n</allow></accessControl></security></a>"
	on, ok := setLiteSpeedTrustedLoopback(cfg, true)
	if !ok || !strings.Contains(on, "ALL, 127.0.0.1T") {
		t.Fatalf("the entry was not added to the server-wide list: %q", on)
	}
	if !strings.Contains(on, "<allow>10.0.0.0/8</allow>") {
		t.Fatalf("a virtual host's list was touched: %q", on)
	}
	if again, ok := setLiteSpeedTrustedLoopback(on, true); ok || again != on {
		t.Fatalf("adding twice changed the file: %q", again)
	}
	off, ok := setLiteSpeedTrustedLoopback(on, false)
	if !ok || strings.Contains(off, "127.0.0.1T") || !strings.Contains(off, "ALL") {
		t.Fatalf("the entry was not taken away cleanly: %q", off)
	}
	if !wellFormedXML(off) || !wellFormedXML(on) {
		t.Fatal("the result is not well-formed")
	}
}

func TestLiteSpeedEmptyAllowListKeepsMeaningEveryone(t *testing.T) {
	cfg := "<security><accessControl><allow></allow></accessControl></security>"
	on, ok := setLiteSpeedTrustedLoopback(cfg, true)
	if !ok || !strings.Contains(on, "ALL, 127.0.0.1T") {
		t.Fatalf("an empty list did not keep meaning everyone: %q", on)
	}
	// With no access control at all, nothing is made up.
	if out, ok := setLiteSpeedTrustedLoopback("<a/>", true); ok || out != "<a/>" {
		t.Fatalf("a file with no access control was changed: %q", out)
	}
}

func TestWellFormedXML(t *testing.T) {
	if !wellFormedXML(`<?xml version="1.0" encoding="ISO-8859-1"?><a><b/></a>`) {
		t.Fatal("a fine file was refused")
	}
	if wellFormedXML("<a><b></a>") {
		t.Fatal("a broken file was accepted")
	}
}

func TestHostsTagIsMatchedWholeNotByPrefix(t *testing.T) {
	line := "127.0.0.1 b.example www.b.example # portbridge-website-loopback:a2"
	if hostsLineHasTag(line, "# portbridge-website-loopback:a") {
		t.Fatal("tunnel a was taken to own tunnel a2's line")
	}
	if !hostsLineHasTag(line, "# portbridge-website-loopback:a2") {
		t.Fatal("the line's own tag was not found")
	}
}

func TestWPConfigBlockGoesBeforeAClosingPHPTag(t *testing.T) {
	out := injectWPConfigProxyBlock("<?php\ndefine('X', 1);\n?>\n", "/* block */")
	i, j := strings.Index(out, "/* block */"), strings.LastIndex(out, "?>")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("the block was put after the closing tag: %q", out)
	}
}
