//go:build freebsd && cgo && integration

package pf

import (
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The NAT-state tests build a small realistic lab, in the same spirit and
// under the same gate (GOPF_TEST_ENABLE_PF=1, PF disabled with no ruleset)
// as integration_states_test.go:
//
//	vnet jail "gopfnat" (10.77.0.2) -- epairNb | epairNa (10.77.0.1) -- host
//	host forwards (net.inet.ip.forwarding=1) out of a tap "external"
//	interface (198.18.254.1/30) with
//	    nat on tapN inet from 10.77.0.0/24 to any -> (tapN)
//	    pass all
//
// A UDP datagram from the jail towards the tap peer makes PF create two
// states: an unmodified one on the epair, and the NAT state on the tap
// whose wire key holds 198.18.254.1 and whose stack key holds the jail's
// address (pfctl -ss shows it as "198.18.254.1:p (10.77.0.2:q) -> ...").
// Nothing leaves the host: the tap peer does not exist. Everything is
// removed afterwards and forwarding is restored; TestMain's safety net
// (natSafetyNet) does the same if a run ends early.

const (
	natJail      = "gopfnat"
	natHostCIDR  = "10.77.0.1/24"
	natGuestCIDR = "10.77.0.2/24"
	natGuest     = "10.77.0.2"
	natSubnet    = "10.77.0.0/24"
)

var (
	natMu         sync.Mutex
	natEpairA     string
	natJailUp     bool
	natSavedFwd   string
	natFwdChanged bool
)

// natSafetyNet removes whatever the NAT lab left behind (no-op when the
// test cleaned up). Called from safetyNet.
func natSafetyNet() {
	natMu.Lock()
	defer natMu.Unlock()
	if natJailUp {
		_ = exec.Command("jail", "-r", natJail).Run()
		natJailUp = false
	}
	if natEpairA != "" {
		_ = exec.Command("pfctl", "-i", natEpairA, "-F", "states").Run()
		_ = exec.Command("ifconfig", natEpairA, "destroy").Run()
		natEpairA = ""
	}
	if natFwdChanged {
		_ = exec.Command("sysctl", "net.inet.ip.forwarding="+natSavedFwd).Run()
		natFwdChanged = false
	}
	_ = exec.Command("pfctl", "-F", "nat").Run()
}

// natLab builds the lab and returns the external tap name. It skips when
// the host cannot do vnet jails or epairs.
func natLab(t *testing.T, c *Client) string {
	t.Helper()
	enableSafePF(t, c)
	tap := createTap(t)

	out, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output()
	if err != nil {
		t.Skipf("sysctl net.inet.ip.forwarding: %v", err)
	}
	natMu.Lock()
	natSavedFwd = strings.TrimSpace(string(out))
	natFwdChanged = true
	natMu.Unlock()
	t.Cleanup(natSafetyNet)
	runCmd(t, "", "sysctl", "net.inet.ip.forwarding=1")

	epb, err := exec.Command("ifconfig", "epair", "create").Output()
	if err != nil {
		t.Skipf("ifconfig epair create: %v", err)
	}
	epA := strings.TrimSpace(string(epb))
	natMu.Lock()
	natEpairA = epA
	natMu.Unlock()
	epB := strings.TrimSuffix(epA, "a") + "b"
	runCmd(t, "", "ifconfig", epA, "inet", natHostCIDR, "up")

	// A jail left by an aborted run would make "jail -c" fail (or worse,
	// keep an old epair): remove it first, and fail loudly if creation
	// still does not work.
	_ = exec.Command("jail", "-r", natJail).Run()
	if out, err := exec.Command("jail", "-c", "name="+natJail, "persist", "vnet",
		"vnet.interface="+epB, "path=/").CombinedOutput(); err != nil {
		t.Fatalf("vnet jail: %v\n%s", err, out)
	}
	natMu.Lock()
	natJailUp = true
	natMu.Unlock()
	runCmd(t, "", "jexec", natJail, "ifconfig", epB, "inet", natGuestCIDR, "up")
	runCmd(t, "", "jexec", natJail, "route", "add", "default", strings.Split(natHostCIDR, "/")[0])

	ruleset := "nat on " + tap + " inet from " + natSubnet + " to any -> (" + tap + ")\npass all\n"
	runCmd(t, ruleset, "pfctl", "-f", "-")
	t.Cleanup(func() { _ = exec.Command("pfctl", "-F", "nat").Run() })
	return tap
}

// natTraffic sends one datagram from the jail through the NAT.
func natTraffic(t *testing.T) {
	t.Helper()
	cmd := exec.Command("jexec", natJail, "nc", "-u", "-w", "1", tapPeer, "9999")
	cmd.Stdin = strings.NewReader("go-freebsd-pf\n")
	_ = cmd.Run() // no reply is expected
	time.Sleep(100 * time.Millisecond)
}

func natStates(t *testing.T, c *Client, f StateFilter) []State {
	t.Helper()
	f.Source = &net.IPNet{IP: net.ParseIP(natGuest), Mask: net.CIDRMask(32, 32)}
	states, err := c.ListStates(f)
	if err != nil {
		t.Fatalf("ListStates(%+v): %v", f, err)
	}
	return states
}

func TestKillStatesNAT(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	tap := natLab(t, c)

	natTraffic(t)
	pf := runCmd(t, "", "pfctl", "-ss")
	t.Logf("pfctl -ss:\n%s", pf)
	if !strings.Contains(pf, "("+natGuest+":") {
		t.Fatalf("no NAT state for %s on %s:\n%s", natGuest, tap, pf)
	}

	// The wire key holds the translated address, so a listing by the
	// guest address finds nothing on the NAT state without NAT.
	if n := len(natStates(t, c, StateFilter{Interface: tap})); n != 0 {
		t.Fatalf("wire-key listing of %s on %s = %d states, want 0", natGuest, tap, n)
	}
	nat := natStates(t, c, StateFilter{Interface: tap, NAT: true})
	if len(nat) != 1 {
		t.Fatalf("NAT-key listing on %s = %d states, want 1: %+v", tap, len(nat), nat)
	}
	if got := nat[0].Source.String(); got == natGuest {
		t.Errorf("State.Source = %s, want the translated wire address", got)
	}

	// Without NAT: the kill by guest address removes only the unmodified
	// state on the epair, the NAT state survives.
	killed, err := c.KillStates(StateFilter{Source: mustCIDR(t, natGuest+"/32")})
	if err != nil {
		t.Fatalf("KillStates (wire key): %v", err)
	}
	if killed != 1 {
		t.Fatalf("wire-key kill removed %d states, want 1 (the unmodified one)", killed)
	}
	if out := runCmd(t, "", "pfctl", "-ss"); !strings.Contains(out, "("+natGuest+":") {
		t.Fatalf("the NAT state did not survive a wire-key kill (the bug NAT fixes):\n%s", out)
	}

	if !natKillSupported {
		// 13.x/14.x: refuse rather than kill by the wrong key.
		_, err := c.KillStates(StateFilter{NAT: true, Source: mustCIDR(t, natGuest+"/32")})
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("KillStates(NAT) = %v; want ErrNotSupported", err)
		}
		return
	}

	// With NAT: the NAT state is killed.
	killed, err = c.KillStates(StateFilter{NAT: true, Source: mustCIDR(t, natGuest+"/32")})
	if err != nil {
		t.Fatalf("KillStates(NAT): %v", err)
	}
	if killed != 1 {
		t.Errorf("KillStates(NAT) killed %d, want 1", killed)
	}
	if n := len(natStates(t, c, StateFilter{NAT: true})); n != 0 {
		t.Fatalf("%d NAT states of %s survive KillStates(NAT)", n, natGuest)
	}
	if out := runCmd(t, "", "pfctl", "-ss"); strings.Contains(out, natGuest) {
		t.Fatalf("pfctl -ss still shows %s:\n%s", natGuest, out)
	}
}

func TestKillStatesNATKillMatch(t *testing.T) {
	c := openClient(t)
	defer c.Close()
	tap := natLab(t, c)
	if !natKillSupported {
		t.Skip("NAT-key kill needs FreeBSD 15")
	}

	natTraffic(t)
	if n := len(natStates(t, c, StateFilter{Interface: tap, NAT: true})); n != 1 {
		t.Fatalf("setup: %d NAT states on %s, want 1", n, tap)
	}
	t.Logf("before:\n%s", runCmd(t, "", "pfctl", "-ss"))

	// pf_killstates_row looks for the peer with the reversed key of the
	// matched state (as an inbound/outbound lookup, per direction). In
	// this topology that key belongs to no state (a reply would be
	// un-translated first), so kill_match removes exactly the matched
	// state and, in particular, not the unmodified state on the epair.
	killed, err := c.KillStates(StateFilter{Interface: tap, NAT: true, KillMatch: true, Source: mustCIDR(t, natGuest+"/32")})
	if err != nil {
		t.Fatalf("KillStates(NAT, KillMatch): %v", err)
	}
	after := runCmd(t, "", "pfctl", "-ss")
	t.Logf("killed %d; after:\n%s", killed, after)
	if killed != 1 {
		t.Errorf("killed %d, want exactly the 1 matched state", killed)
	}
	if strings.Contains(after, "("+natGuest+":") {
		t.Errorf("NAT state survives:\n%s", after)
	}
	if !strings.Contains(after, "<- "+natGuest+":") {
		t.Errorf("the unmodified epair state must not be a kill_match peer:\n%s", after)
	}
}
