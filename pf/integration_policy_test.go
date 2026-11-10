//go:build freebsd && cgo && integration

package pf

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

// pfctlRules returns `pfctl -a <testAnchor> -sr`, the reference rendering of
// what the kernel holds. It only reads; PF is not enabled or changed.
func pfctlRules(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("pfctl", "-a", testAnchor, "-sr").CombinedOutput()
	if err != nil {
		t.Fatalf("pfctl -a %s -sr: %v\n%s", testAnchor, err, out)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestBlockPolicyAndRtableRoundTrip(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	cleanupAnchor(t, c)
	defer cleanupAnchor(t, c)

	zero := 0
	rules := []Rule{
		{Action: ActionBlock, Direction: DirectionIn, AF: AddressFamilyIPv4}, // drop
		{Action: ActionBlock, Direction: DirectionIn, AF: AddressFamilyIPv4, BlockPolicy: BlockPolicyReturn},
		{Action: ActionBlock, Direction: DirectionIn, AF: AddressFamilyIPv4, Protocol: ProtocolTCP, BlockPolicy: BlockPolicyReturnRST},
		{Action: ActionBlock, Direction: DirectionIn, AF: AddressFamilyIPv4, BlockPolicy: BlockPolicyReturnICMP},
		{Action: ActionPass, Direction: DirectionOut, AF: AddressFamilyIPv4},
		{Action: ActionPass, Direction: DirectionOut, AF: AddressFamilyIPv4, Rtable: &zero},
	}
	if err := c.ReplaceRules(testAnchor, rules); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}

	got, err := c.ListRules(RuleQuery{Anchor: testAnchor, RuleSet: RuleSetFilter})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(got) != len(rules) {
		t.Fatalf("got %d rules, want %d", len(got), len(rules))
	}
	for i, r := range rules {
		if got[i].Action != r.Action || got[i].BlockPolicy != r.BlockPolicy {
			t.Errorf("rule %d: got %v/%v, want %v/%v", i,
				got[i].Action, got[i].BlockPolicy, r.Action, r.BlockPolicy)
		}
		switch {
		case r.Rtable == nil && got[i].Rtable != nil:
			t.Errorf("rule %d: unset rtable read back as %d", i, *got[i].Rtable)
		case r.Rtable != nil && (got[i].Rtable == nil || *got[i].Rtable != *r.Rtable):
			t.Errorf("rule %d: rtable %d did not round trip", i, *r.Rtable)
		}
	}

	// What pfctl prints is the reference.
	lines := pfctlRules(t)
	t.Logf("pfctl -a %s -sr:\n%s", testAnchor, strings.Join(lines, "\n"))
	if len(lines) != len(rules) {
		t.Fatalf("pfctl printed %d rules, want %d", len(lines), len(rules))
	}
	want := []string{"block drop in ", "block return in ", "block return-rst in ", "block return-icmp(port-unr) in "}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("rule %d: %q does not start with %q", i, lines[i], w)
		}
	}
	for i, l := range lines {
		hasRtable := strings.Contains(l, "rtable")
		if wantRtable := i == 5; hasRtable != wantRtable {
			t.Errorf("rule %d: %q: rtable present = %v, want %v", i, l, hasRtable, wantRtable)
		}
	}
	if !strings.Contains(lines[5], "rtable 0") {
		t.Errorf("explicit rtable 0 missing: %q", lines[5])
	}
}

func TestRuleFieldsAgainstPfctl(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	cleanupAnchor(t, c)
	defer cleanupAnchor(t, c)

	echo := uint8(8)
	rules := []Rule{
		{Action: ActionPass, Direction: DirectionOut, Protocol: ProtocolTCP, KeepState: true, TCPFlags: FlagsSA(),
			Destination: Address{Interface: "self"}},
		{Action: ActionPass, Direction: DirectionIn, KeepState: true,
			Source: Address{Interface: "lo0", IfaceFlags: IfaceNetwork}},
		{Action: ActionPass, Protocol: ProtocolICMP, ICMPType: &echo, KeepState: true,
			Source: Address{IP: net.ParseIP("10.9.9.9")}},
		{Action: ActionBlock, Direction: DirectionIn, Protocol: ProtocolTCP, BlockPolicy: BlockPolicyReturnRST,
			Destination: Address{Network: mustCIDR(t, "fd00:9::/64")}},
	}
	if err := c.ReplaceRules(testAnchor, rules); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}
	lines := pfctlRules(t)
	t.Logf("pfctl:\n%s", strings.Join(lines, "\n"))
	wantSub := []string{
		"flags S/SA keep state",
		"from (lo0:network) ",
		"inet proto icmp from 10.9.9.9 to any icmp-type echoreq keep state",
		"block return-rst in inet6 proto tcp from any to fd00:9::/64",
	}
	if len(lines) != len(wantSub) {
		t.Fatalf("pfctl printed %d rules", len(lines))
	}
	for i, w := range wantSub {
		if !strings.Contains(lines[i], w) {
			t.Errorf("rule %d: %q does not contain %q", i, lines[i], w)
		}
	}
	if !strings.Contains(lines[0], "to (self)") {
		t.Errorf("rule 0: %q lacks `to (self)`", lines[0])
	}

	got, err := c.ListRules(RuleQuery{Anchor: testAnchor, RuleSet: RuleSetFilter})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if g := got[0]; g.Destination.Interface != "self" || g.TCPFlags != FlagsSA() || g.Destination.Any {
		t.Errorf("rule 0 read back as %+v", g)
	}
	if g := got[1]; g.Source.Interface != "lo0" || g.Source.IfaceFlags != IfaceNetwork {
		t.Errorf("rule 1 read back as %+v", g.Source)
	}
	if g := got[2]; g.ICMPType == nil || *g.ICMPType != 8 || g.ICMPCode != nil || g.AF != AddressFamilyIPv4 {
		t.Errorf("rule 2 read back as %+v", g)
	}
	if g := got[3]; g.AF != AddressFamilyIPv6 || g.BlockPolicy != BlockPolicyReturnRST {
		t.Errorf("rule 3 read back as %+v", g)
	}
}

func TestMainRulesetHasAnchor(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	// Loads `anchor "go-freebsd-pf-test/*"` and `pass all no state` into the
	// main ruleset (only when PF is disabled with an empty ruleset and
	// GOPF_TEST_ENABLE_PF=1) and restores the empty state on cleanup.
	enableSafePF(t, c)

	for path, want := range map[string]bool{
		"go-freebsd-pf-test/*": true,
		"go-freebsd-pf-test":   false, // the wildcard is part of the call
		"no-such-anchor/*":     false,
	} {
		got, err := c.MainRulesetHasAnchor(path)
		if err != nil {
			t.Fatalf("MainRulesetHasAnchor(%q): %v", path, err)
		}
		if got != want {
			t.Errorf("MainRulesetHasAnchor(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestICMPCodeZeroAndFamilyInference(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	cleanupAnchor(t, c)
	defer cleanupAnchor(t, c)

	unreach, netUnreach, echo6 := uint8(3), uint8(0), uint8(128)
	rules := []Rule{
		{Action: ActionPass, Protocol: ProtocolICMP, ICMPType: &unreach, ICMPCode: &netUnreach, KeepState: true},
		{Action: ActionPass, Protocol: ProtocolICMPv6, ICMPType: &echo6, KeepState: true},
		{Action: ActionPass, Source: Address{IP: net.ParseIP("::ffff:10.1.2.3")}, KeepState: true},
	}
	if err := c.ReplaceRules(testAnchor, rules); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}
	lines := pfctlRules(t)
	t.Logf("pfctl:\n%s", strings.Join(lines, "\n"))
	got, err := c.ListRules(RuleQuery{Anchor: testAnchor, RuleSet: RuleSetFilter})
	if err != nil || len(got) != 3 {
		t.Fatalf("ListRules: %v (%d rules)", err, len(got))
	}
	if g := got[0]; g.AF != AddressFamilyIPv4 || g.ICMPType == nil || *g.ICMPType != 3 || g.ICMPCode == nil || *g.ICMPCode != 0 {
		t.Errorf("rule 0 (code 0 edge): %+v", g)
	}
	if g := got[1]; g.AF != AddressFamilyIPv6 || g.ICMPType == nil || *g.ICMPType != 128 || g.ICMPCode != nil {
		t.Errorf("rule 1: %+v", g)
	}
	if g := got[2]; g.AF != AddressFamilyIPv4 {
		t.Errorf("rule 2 (v4-mapped): AF %v", g.AF)
	}
	for i, w := range []string{"inet proto icmp ", "inet6 proto ipv6-icmp ", "inet from 10.1.2.3 "} {
		if i < len(lines) && !strings.Contains(lines[i], w) {
			t.Errorf("rule %d: %q lacks %q", i, lines[i], w)
		}
	}
}

func TestMainRulesetHasAbsoluteAnchor(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	enableSafePF(t, c)
	// Replaces the safe ruleset (same restore path) with an absolute call.
	runCmd(t, "anchor \"/go-freebsd-pf-test/*\"\npass all no state\n", "pfctl", "-f", "-")
	for path, want := range map[string]bool{
		"go-freebsd-pf-test/*":  true,
		"/go-freebsd-pf-test/*": true,
		"go-freebsd-pf-test":    false,
	} {
		got, err := c.MainRulesetHasAnchor(path)
		if err != nil || got != want {
			t.Errorf("MainRulesetHasAnchor(%q) = %v, %v; want %v", path, got, err, want)
		}
	}
}
