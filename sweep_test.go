package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These run the real helper against stand-in firewall and network tools (see
// gre_helper_test.go) and check the promise that nothing of a deleted tunnel's is
// ever left in the firewall, and that nothing else is ever touched.

const (
	someoneElses = `-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT`
	otherComment = `-A INPUT -p tcp -m tcp --dport 80 -m comment --comment "my web server" -j ACCEPT`
	lookalike    = `-A INPUT -p tcp -m tcp --dport 81 -m comment --comment "portbridge" -j ACCEPT`
	lookalike2   = `-A INPUT -p tcp -m tcp --dport 82 -m comment --comment "notportbridge:ae" -j ACCEPT`
)

func ruleFor(tag, dport, target string) string {
	return `-A INPUT -p tcp -m tcp --dport ` + dport + ` -m comment --comment "` + tag + `" -j ` + target
}

func (r *greRig) putRules(file string, rules ...string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.state, file), []byte(strings.Join(rules, "\n")+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *greRig) rulesIn(file string) string {
	b, _ := os.ReadFile(filepath.Join(r.state, file))
	return string(b)
}

func mustContain(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func mustNotContain(t *testing.T, got string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(got, w) {
			t.Errorf("should not contain %q, but:\n%s", w, got)
		}
	}
}

// Rules of tunnels that no longer exist go, from IPv4 and IPv6; rules of tunnels
// that do exist stay; nobody else's rules are touched, however much they look alike.
func TestSweepRemovesOnlyWhatBelongsToDeletedTunnels(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("alive", "")
	r.putRules("rules",
		someoneElses,
		ruleFor("portbridge:ae", "2354", "DROP"),
		ruleFor("portbridge:aeza-2", "8756", "ACCEPT"),
		ruleFor("portbridge:alive", "9443", "DROP"),
		otherComment, lookalike, lookalike2,
	)
	r.putRules("rules6", ruleFor("portbridge:ae", "2354", "DROP"), ruleFor("portbridge:alive", "9443", "DROP"))

	out, code := r.run("sweep")
	if code != 0 {
		t.Fatalf("sweep failed (%d): %s", code, out)
	}
	mustContain(t, out, "swept 3")
	v4, v6 := r.rulesIn("rules"), r.rulesIn("rules6")
	mustNotContain(t, v4, `--comment "portbridge:ae"`, "portbridge:aeza-2")
	mustNotContain(t, v6, `--comment "portbridge:ae"`)
	mustContain(t, v4, "portbridge:alive", someoneElses, otherComment, lookalike, lookalike2)
	mustContain(t, v6, "portbridge:alive")
}

func TestSweepSaysSoWhenThereIsNothingToDo(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("alive", "")
	r.putRules("rules", someoneElses, ruleFor("portbridge:alive", "9443", "DROP"))
	out, code := r.run("sweep")
	if code != 0 || !strings.Contains(out, "nothing left behind") {
		t.Fatalf("(%d) %s", code, out)
	}
	quiet, _ := r.run("sweep", "quiet")
	if strings.TrimSpace(quiet) != "" {
		t.Fatalf("the quiet form said something: %q", quiet)
	}
}

// With no settings directory it cannot tell what is wanted, so it removes nothing.
func TestSweepDoesNothingWithoutASettingsDirectory(t *testing.T) {
	r := newGRERig(t)
	r.putRules("rules", ruleFor("portbridge:ae", "2354", "DROP"))
	if err := os.RemoveAll(r.conf); err != nil {
		t.Fatal(err)
	}
	out, code := r.run("sweep")
	if code != 0 {
		t.Fatalf("(%d) %s", code, out)
	}
	mustContain(t, r.rulesIn("rules"), "portbridge:ae")
}

// A GRE link, its firewall rule and its interface are kept while a tunnel uses
// them and swept when none does.
func TestSweepRemovesAGRELinkNoTunnelUses(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("g", "on")
	if _, code := r.run("apply", "g"); code != 0 || !r.linkExists() {
		t.Fatalf("no link to begin with")
	}
	// Still wanted: stays, however often it is swept.
	if _, code := r.run("sweep"); code != 0 || !r.linkExists() || r.rules() == "" {
		t.Fatalf("a link in use was swept")
	}
	// The tunnel's settings vanish without anything cleaning up after it.
	if err := os.Remove(filepath.Join(r.conf, "g.conf")); err != nil {
		t.Fatal(err)
	}
	out, code := r.run("sweep")
	if code != 0 {
		t.Fatalf("(%d) %s", code, out)
	}
	mustContain(t, out, "removed the GRE link pbgc848d733")
	if r.linkExists() || r.rules() != "" {
		t.Fatalf("the link or its rule is still there: link=%v rules=%q", r.linkExists(), r.rules())
	}
}

// Starting any tunnel clears away what deleted ones left, so it heals by itself.
func TestApplyClearsLeftoversOfDeletedTunnels(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("fresh", "")
	r.putRules("rules", ruleFor("portbridge:ghost", "7000", "DROP"), someoneElses)
	if out, code := r.run("apply", "fresh"); code != 0 {
		t.Fatalf("(%d) %s", code, out)
	}
	got := r.rulesIn("rules")
	mustNotContain(t, got, "portbridge:ghost")
	mustContain(t, got, someoneElses)
}

// Uninstalling removes everything of PortBridge's, whatever the settings say.
func TestSweepAllRemovesEverythingTaggedAndNothingElse(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("alive", "")
	r.tunnel("g", "on")
	if _, code := r.run("apply", "g"); code != 0 {
		t.Fatalf("apply failed")
	}
	r.putRules("rules",
		someoneElses,
		ruleFor("portbridge:alive", "9443", "DROP"),
		ruleFor("portbridge-gre:pbgc848d733", "1", "ACCEPT"),
		otherComment,
	)
	out, code := r.run("sweep", "all")
	if code != 0 {
		t.Fatalf("(%d) %s", code, out)
	}
	got := r.rulesIn("rules")
	mustNotContain(t, got, "portbridge")
	mustContain(t, got, someoneElses, otherComment)
	if r.linkExists() {
		t.Fatalf("the GRE link survived an uninstall sweep")
	}
}

// Deleting a tunnel the ordinary way, then sweeping, leaves nothing; and a
// listing with quoted comments (as nftables prints) is understood.
func TestRemoveThenSweepLeavesNothing(t *testing.T) {
	r := newGRERig(t)
	r.tunnel("t", "")
	r.putRules("rules", ruleFor("portbridge:t", "9443", "DROP"), ruleFor("portbridge:t", "9443", "ACCEPT"))
	if out, code := r.run("remove", "t"); code != 0 {
		t.Fatalf("(%d) %s", code, out)
	}
	mustNotContain(t, r.rulesIn("rules"), "portbridge:t")
	r.putRules("rules", ruleFor("portbridge:t", "9443", "DROP"))
	if err := os.Remove(filepath.Join(r.conf, "t.conf")); err != nil {
		t.Fatal(err)
	}
	if _, code := r.run("sweep", "quiet"); code != 0 {
		t.Fatalf("sweep failed")
	}
	mustNotContain(t, r.rulesIn("rules"), "portbridge:t")
}

func TestSweepRefusesAnUnknownArgument(t *testing.T) {
	r := newGRERig(t)
	if _, code := r.run("sweep", "everything"); code == 0 {
		t.Fatalf("an unknown argument was accepted")
	}
}
