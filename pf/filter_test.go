package pf

import (
	"encoding/binary"
	"math"
	"net"
	"testing"
)

func TestMatchesFilterInterface(t *testing.T) {
	// A floating state (the default state-policy) is attached to "all";
	// the interface it was created on is in OrigInterface.
	floating := State{Interface: "all", OrigInterface: "tap3",
		Source: net.ParseIP("198.18.254.1"), Destination: net.ParseIP("198.18.254.2")}
	bound := State{Interface: "tap3", OrigInterface: "tap3"}

	tests := []struct {
		name string
		s    State
		f    StateFilter
		want bool
	}{
		{"empty filter", floating, StateFilter{}, true},
		{"floating by creating interface", floating, StateFilter{Interface: "tap3"}, true},
		// The kernel's kill/clear compare a floating state's original
		// interface only, so "all" matches nothing there; listing agrees.
		{"floating not by all", floating, StateFilter{Interface: "all"}, false},
		{"floating other interface", floating, StateFilter{Interface: "tap4"}, false},
		{"if-bound", bound, StateFilter{Interface: "tap3"}, true},
		{"if-bound other interface", bound, StateFilter{Interface: "re0"}, false},
		{"if-bound ignores orig", State{Interface: "tap3", OrigInterface: "tap9"}, StateFilter{Interface: "tap9"}, false},
		{"source match", floating, StateFilter{Interface: "tap3", Source: mustCIDR(t, "198.18.254.0/30")}, true},
		{"source mismatch", floating, StateFilter{Source: mustCIDR(t, "192.0.2.0/24")}, false},
		{"destination match", floating, StateFilter{Destination: mustCIDR(t, "198.18.254.2/32")}, true},
		{"destination mismatch", floating, StateFilter{Destination: mustCIDR(t, "198.18.254.1/32")}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesFilter(tc.s, tc.f); got != tc.want {
				t.Fatalf("matchesFilter = %v, want %v", got, tc.want)
			}
		})
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOrientWireKey(t *testing.T) {
	local, remote := net.ParseIP("198.18.254.1"), net.ParseIP("198.18.254.2")

	// Outbound: the wire key holds the destination in slot 0 and the
	// initiator in slot 1 (pfctl prints addr[1] -> addr[0]).
	src, dst, sp, dp := orientWireKey(DirectionOut, [2]net.IP{remote, local}, [2]uint16{40021, 24614})
	if !src.Equal(local) || !dst.Equal(remote) || sp != 24614 || dp != 40021 {
		t.Errorf("out: got %v:%d -> %v:%d", src, sp, dst, dp)
	}

	// Inbound: slot 0 is the initiator (pfctl prints addr[1] <- addr[0]).
	src, dst, sp, dp = orientWireKey(DirectionIn, [2]net.IP{remote, local}, [2]uint16{51000, 22})
	if !src.Equal(remote) || !dst.Equal(local) || sp != 51000 || dp != 22 {
		t.Errorf("in: got %v:%d -> %v:%d", src, sp, dst, dp)
	}
}

func TestNetworkOrder(t *testing.T) {
	// A value the kernel stored with htonl/htobe64 reads back, in host
	// memory, with its bytes in network order.
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 300)
	if got := ntohl(binary.NativeEndian.Uint32(b4[:])); got != 300 {
		t.Errorf("ntohl = %d, want 300", got)
	}
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], 0x0102030405060708)
	if got := be64toh(binary.NativeEndian.Uint64(b8[:])); got != 0x0102030405060708 {
		t.Errorf("be64toh = %#x", got)
	}
}

func TestStatesBufLen(t *testing.T) {
	const e = 384 // sizeof(struct pf_state_export)
	max := statesMaxLen(e)
	if max%e != 0 || max > 256<<20 || max > math.MaxInt32 {
		t.Fatalf("statesMaxLen = %d: not a bounded multiple of %d", max, e)
	}
	if got, want := statesBufLen(0, e), 16*e; got != want {
		t.Errorf("statesBufLen(0) = %d, want %d", got, want)
	}
	if got, want := statesBufLen(-5, e), 16*e; got != want {
		t.Errorf("statesBufLen(negative) = %d, want %d", got, want)
	}
	// probe of 100 states -> 125 + 16 entries
	if got, want := statesBufLen(100*e, e), 141*e; got != want {
		t.Errorf("statesBufLen(100 entries) = %d, want %d", got, want)
	}
	// Clamped, still a multiple of the entry size.
	if got := statesBufLen(math.MaxInt32, e); got != max {
		t.Errorf("statesBufLen(MaxInt32) = %d, want clamp %d", got, max)
	}
}

func TestStatesNext(t *testing.T) {
	const e = 384
	buf := 141 * e
	max := statesMaxLen(e)

	// First roomy pass: not trusted yet, repeat to confirm.
	done, next, err := statesNext(-1, 100*e, buf, e)
	if done || err != nil || next < buf {
		t.Fatalf("first roomy pass: done=%v next=%d err=%v; want a confirming pass", done, next, err)
	}
	// Second roomy pass with the same count: complete.
	if done, _, err := statesNext(100*e, 100*e, buf, e); !done || err != nil {
		t.Fatalf("confirmed pass: done=%v err=%v; want done", done, err)
	}
	// Same count but no room left: a row may not have fitted, grow.
	done, next, err = statesNext(buf-8*e, buf-8*e, buf, e)
	if done || err != nil || next <= buf {
		t.Fatalf("tight pass: done=%v next=%d err=%v; want a larger buffer", done, next, err)
	}
	// Count changed: not stable, retry.
	if done, _, err := statesNext(90*e, 100*e, buf, e); done || err != nil {
		t.Fatalf("changed count: done=%v err=%v; want retry", done, err)
	}
	// Growth is clamped; at the cap with no room left it is an error.
	if _, next, _ := statesNext(-1, max/2, max/2+e, e); next > max {
		t.Fatalf("next %d exceeds cap %d", next, max)
	}
	if _, _, err := statesNext(-1, max, max, e); err == nil {
		t.Fatal("full buffer at the cap: want an error, not a short list")
	}
	// Malformed replies are rejected before any entry is read.
	for _, ret := range []int{-e, buf + e, 100*e + 1} {
		if _, _, err := statesNext(-1, ret, buf, e); err == nil {
			t.Errorf("returned %d of %d: want an error", ret, buf)
		}
	}
}
