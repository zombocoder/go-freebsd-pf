//go:build freebsd && cgo && integration

package pf

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Tests in this file need PF enabled so that real states exist. They only
// run when GOPF_TEST_ENABLE_PF=1 and PF is disabled with an empty main
// ruleset; they then load a minimal main ruleset
//
//	anchor "go-freebsd-pf-test/*"
//	pass all no state
//
// which passes everything (it cannot cut off ssh) and creates states only
// for rules the tests put into go-freebsd-pf-test/... anchors. On cleanup
// PF is disabled again and the main ruleset flushed, which restores the
// "disabled, no ruleset" starting point. Traffic is sent out of a tap
// interface the test creates and destroys.

const (
	statesAnchor = testAnchor + "/states"
	rulesAnchor  = testAnchor + "/rules"
	safeRuleset  = "anchor \"go-freebsd-pf-test/*\"\npass all no state\n"
	tapLocalCIDR = "198.18.254.1/30"
	tapPeer      = "198.18.254.2"
)

func runCmd(t *testing.T, stdin string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// enableSafePF loads the safe main ruleset and enables PF, or skips.
func enableSafePF(t *testing.T, c *Client) {
	t.Helper()
	if os.Getenv("GOPF_TEST_ENABLE_PF") != "1" {
		t.Skip("set GOPF_TEST_ENABLE_PF=1 to allow enabling PF with a pass-all ruleset")
	}
	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Running {
		t.Skip("PF is already running; not touching a live firewall")
	}
	for _, what := range []string{"rules", "nat"} {
		out := runCmd(t, "", "pfctl", "-s", what)
		if len(bytes.TrimSpace([]byte(out))) != 0 {
			t.Skipf("main %s ruleset is not empty; not touching it:\n%s", what, out)
		}
	}

	runCmd(t, safeRuleset, "pfctl", "-f", "-")
	t.Cleanup(func() {
		// Order matters: stop filtering first, then drop the ruleset.
		_ = exec.Command("pfctl", "-d").Run()
		_ = exec.Command("pfctl", "-F", "rules").Run()
	})
	if err := c.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

// createTap creates a throwaway tap interface with a /30 address.
func createTap(t *testing.T) string {
	t.Helper()
	name := strings.TrimSpace(runCmd(t, "", "ifconfig", "tap", "create"))
	t.Cleanup(func() { _ = exec.Command("ifconfig", name, "destroy").Run() })
	// Holding the character device open brings the link up; with "no
	// carrier" the stack drops output before PF ever sees it.
	dev, err := os.OpenFile("/dev/"+name, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/%s: %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })
	// Runs first: drop any state a failed test left on the tap.
	t.Cleanup(func() { _ = exec.Command("pfctl", "-i", name, "-F", "states").Run() })
	runCmd(t, "", "ifconfig", name, "inet", tapLocalCIDR, "up")
	return name
}

// sendUDP sends a datagram towards the tap peer so PF creates an
// outbound state on the tap. Delivery does not matter.
func sendUDP(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(tapPeer), Port: port})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("go-freebsd-pf"))
}

// statesOn counts states on ifname, using the library when it can list
// states and pfctl otherwise.
func statesOn(t *testing.T, c *Client, ifname string) int {
	t.Helper()
	states, err := c.ListStates(StateFilter{Interface: ifname})
	if err == nil {
		return len(states)
	}
	t.Logf("ListStates: %v; counting with pfctl", err)
	out := runCmd(t, "", "pfctl", "-s", "states", "-i", ifname)
	return len(strings.Fields(strings.TrimSpace(out))) / 6
}

func passOutRule(ifname string) Rule {
	return Rule{
		Action:      ActionPass,
		Direction:   DirectionOut,
		Interface:   ifname,
		Protocol:    ProtocolUDP,
		AF:          AddressFamilyIPv4,
		Source:      Address{Any: true},
		Destination: Address{Any: true},
		Quick:       true,
		KeepState:   true,
		Label:       "gopf-states",
	}
}

func TestIsEnabled(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	enabled, err := c.IsEnabled()
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if enabled != st.Running {
		t.Fatalf("IsEnabled=%v but Status.Running=%v", enabled, st.Running)
	}
}

func TestStatusWhileEnabled(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	enableSafePF(t, c)

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Running {
		t.Fatal("expected Running after Enable")
	}
	if st.Since.IsZero() || st.Since.Unix() == 0 {
		t.Errorf("expected a Since timestamp, got %v", st.Since)
	}
	if d := time.Since(st.Since); d < -time.Minute || d > time.Hour {
		t.Errorf("Since %v is not close to now (%v ago)", st.Since, d)
	}
	enabled, err := c.IsEnabled()
	if err != nil || !enabled {
		t.Fatalf("IsEnabled = %v, %v; want true, nil", enabled, err)
	}
	t.Logf("status: %+v", st)
}

func TestListRulesInAnchor(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	ifname := createTap(t)

	_ = c.ClearRules(rulesAnchor, RuleSetFilter)
	defer func() { _ = c.ClearRules(rulesAnchor, RuleSetFilter) }()

	_, src, _ := net.ParseCIDR("192.0.2.0/24")
	want := []Rule{
		{
			Action:          ActionBlock,
			Direction:       DirectionIn,
			Interface:       ifname,
			Protocol:        ProtocolTCP,
			AF:              AddressFamilyIPv4,
			Source:          Address{Network: src},
			Destination:     Address{Any: true},
			DestinationPort: PortMatcher{Operator: PortOpEq, From: 2222},
			Quick:           true,
			Label:           "gopf-block",
		},
		passOutRule(ifname),
	}
	if err := c.ReplaceRules(rulesAnchor, want); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}

	got, err := c.ListRules(RuleQuery{Anchor: rulesAnchor, RuleSet: RuleSetFilter})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(got), len(want), got)
	}

	b := got[0]
	if b.Nr != 0 || b.Action != ActionBlock || b.Direction != DirectionIn ||
		b.Interface != ifname || b.Protocol != ProtocolTCP ||
		b.AF != AddressFamilyIPv4 || !b.Quick || b.Label != "gopf-block" {
		t.Errorf("rule 0 mismatch: %+v", b)
	}
	if b.Source.Network == nil || b.Source.Network.String() != "192.0.2.0/24" {
		t.Errorf("rule 0 source = %+v, want 192.0.2.0/24", b.Source)
	}
	if !b.Destination.Any {
		t.Errorf("rule 0 destination = %+v, want any", b.Destination)
	}
	if b.DestinationPort.Operator != PortOpEq || b.DestinationPort.From != 2222 {
		t.Errorf("rule 0 dst port = %+v, want = 2222", b.DestinationPort)
	}

	p := got[1]
	if p.Nr != 1 || p.Action != ActionPass || p.Direction != DirectionOut ||
		p.Interface != ifname || p.Protocol != ProtocolUDP || !p.KeepState ||
		p.Label != "gopf-states" {
		t.Errorf("rule 1 mismatch: %+v", p)
	}

	// pfctl must agree that the rules live in the anchor.
	out := runCmd(t, "", "pfctl", "-a", rulesAnchor, "-s", "rules")
	if !strings.Contains(out, "port = 2222") || !strings.Contains(out, ifname) {
		t.Errorf("pfctl -a %s -sr does not show the rules:\n%s", rulesAnchor, out)
	}

	if err := c.ClearRules(rulesAnchor, RuleSetFilter); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	got, err = c.ListRules(RuleQuery{Anchor: rulesAnchor, RuleSet: RuleSetFilter})
	if err != nil {
		t.Fatalf("ListRules after ClearRules: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 rules after ClearRules, got %d", len(got))
	}
}

func TestKillStatesByInterface(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	ifname := createTap(t)
	enableSafePF(t, c)

	_ = c.ClearRules(statesAnchor, RuleSetFilter)
	defer func() { _ = c.ClearRules(statesAnchor, RuleSetFilter) }()
	if err := c.ReplaceRules(statesAnchor, []Rule{passOutRule(ifname)}); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}

	for port := 40001; port <= 40003; port++ {
		sendUDP(t, port)
	}
	if n := statesOn(t, c, ifname); n < 3 {
		t.Fatalf("expected >= 3 states on %s, got %d", ifname, n)
	}

	// Killing on another interface must not touch ours.
	if _, err := c.KillStates(StateFilter{Interface: "lo0"}); err != nil {
		t.Fatalf("KillStates(lo0): %v", err)
	}
	if n := statesOn(t, c, ifname); n < 3 {
		t.Fatalf("KillStates(lo0) removed %s states: %d left", ifname, n)
	}

	killed, err := c.KillStates(StateFilter{Interface: ifname})
	if err != nil {
		t.Fatalf("KillStates(%s): %v", ifname, err)
	}
	if killed < 3 {
		t.Errorf("KillStates(%s) killed %d, want >= 3", ifname, killed)
	}
	if n := statesOn(t, c, ifname); n != 0 {
		t.Fatalf("expected 0 states on %s after KillStates, got %d", ifname, n)
	}
}

func TestClearStatesByInterface(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	ifname := createTap(t)
	enableSafePF(t, c)

	_ = c.ClearRules(statesAnchor, RuleSetFilter)
	defer func() { _ = c.ClearRules(statesAnchor, RuleSetFilter) }()
	if err := c.ReplaceRules(statesAnchor, []Rule{passOutRule(ifname)}); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}

	sendUDP(t, 40011)
	sendUDP(t, 40012)
	if n := statesOn(t, c, ifname); n < 2 {
		t.Fatalf("expected >= 2 states on %s, got %d", ifname, n)
	}

	cleared, err := c.ClearStates(StateFilter{Interface: ifname})
	if err != nil {
		t.Fatalf("ClearStates(%s): %v", ifname, err)
	}
	if cleared < 2 {
		t.Errorf("ClearStates(%s) cleared %d, want >= 2", ifname, cleared)
	}
	if n := statesOn(t, c, ifname); n != 0 {
		t.Fatalf("expected 0 states on %s after ClearStates, got %d", ifname, n)
	}
}

func TestListStatesOnInterface(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	ifname := createTap(t)
	enableSafePF(t, c)

	_ = c.ClearRules(statesAnchor, RuleSetFilter)
	defer func() { _ = c.ClearRules(statesAnchor, RuleSetFilter) }()
	if err := c.ReplaceRules(statesAnchor, []Rule{passOutRule(ifname)}); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}
	sendUDP(t, 40021)

	states, err := c.ListStates(StateFilter{Interface: ifname})
	if err != nil {
		t.Fatalf("ListStates: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected 1 state on %s, got %d: %+v", ifname, len(states), states)
	}
	s := states[0]
	if s.Protocol != ProtocolUDP || s.DestPort != 40021 ||
		!s.Destination.Equal(net.ParseIP(tapPeer)) || s.Direction != DirectionOut {
		t.Errorf("unexpected state: %+v", s)
	}
	if s.OrigInterface != ifname || s.Expire <= 0 || s.Expire > time.Hour {
		t.Errorf("unexpected interface/expiry: %+v", s)
	}
	t.Logf("state: %+v", s)
	_, _ = c.KillStates(StateFilter{Interface: ifname})
}
