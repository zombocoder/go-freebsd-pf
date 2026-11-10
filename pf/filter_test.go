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

func TestMatchesFilterNAT(t *testing.T) {
	// An outbound NAT state as pfctl -ss shows it: the wire key carries
	// the translated address, the stack key the guest's own.
	guest, ext, remote := net.ParseIP("10.77.0.2"), net.ParseIP("192.0.2.9"), net.ParseIP("198.51.100.7")
	s := State{
		Interface: "all", OrigInterface: "re0", Direction: DirectionOut,
		Source: ext, Destination: remote,
		natSource: guest, natDestination: remote,
	}
	tests := []struct {
		name string
		f    StateFilter
		want bool
	}{
		{"guest source, wire key", StateFilter{Source: mustCIDR(t, "10.77.0.2/32")}, false},
		{"guest source, NAT key", StateFilter{NAT: true, Source: mustCIDR(t, "10.77.0.2/32")}, true},
		{"external source, wire key", StateFilter{Source: mustCIDR(t, "192.0.2.9/32")}, true},
		{"external source, NAT key", StateFilter{NAT: true, Source: mustCIDR(t, "192.0.2.9/32")}, false},
		{"destination, NAT key", StateFilter{NAT: true, Destination: mustCIDR(t, "198.51.100.7/32")}, true},
		{"NAT without addresses", StateFilter{NAT: true}, true},
		{"KillMatch does not filter", StateFilter{KillMatch: true, Source: mustCIDR(t, "192.0.2.9/32")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesFilter(s, tc.f); got != tc.want {
				t.Fatalf("matchesFilter = %v, want %v", got, tc.want)
			}
		})
	}
}

// pfKeyBytes lays out a pf_state_key_export address pair the way the kernel
// exports it: two 16-byte pf_addr slots.
func pfKeyBytes(a0, a1 string) (b [32]byte) {
	copy(b[0:], net.ParseIP(a0).To16()[12:])
	copy(b[16:], net.ParseIP(a1).To16()[12:])
	return
}

func TestDecodeStateKey(t *testing.T) {
	// A translated state keeps distinct wire and stack keys. Keys are in
	// inbound orientation: slot 0 is the initiator for "in", slot 1 for "out".
	wire := pfKeyBytes("198.51.100.7", "192.0.2.9")  // remote, translated
	stack := pfKeyBytes("198.51.100.7", "10.77.0.2") // remote, guest
	wp, sp := [2]uint16{9999, 54000}, [2]uint16{9999, 32000}

	src, dst, sport, dport := decodeStateKey(AddressFamilyIPv4, wire, wp, DirectionOut)
	if !src.Equal(net.ParseIP("192.0.2.9")) || !dst.Equal(net.ParseIP("198.51.100.7")) || sport != 54000 || dport != 9999 {
		t.Errorf("wire/out = %v:%d -> %v:%d", src, sport, dst, dport)
	}
	src, _, sport, _ = decodeStateKey(AddressFamilyIPv4, stack, sp, DirectionOut)
	if !src.Equal(net.ParseIP("10.77.0.2")) || sport != 32000 {
		t.Errorf("stack/out src = %v:%d, want 10.77.0.2:32000", src, sport)
	}

	// Inbound: slot 0 initiates.
	in := pfKeyBytes("10.77.0.2", "198.51.100.7")
	src, dst, sport, dport = decodeStateKey(AddressFamilyIPv4, in, [2]uint16{32000, 9999}, DirectionIn)
	if !src.Equal(net.ParseIP("10.77.0.2")) || !dst.Equal(net.ParseIP("198.51.100.7")) || sport != 32000 || dport != 9999 {
		t.Errorf("stack/in = %v:%d -> %v:%d", src, sport, dst, dport)
	}

	// IPv6 uses all 16 bytes of each slot.
	var b6 [32]byte
	copy(b6[0:], net.ParseIP("2001:db8::1"))
	copy(b6[16:], net.ParseIP("2001:db8::2"))
	src, dst, _, _ = decodeStateKey(AddressFamilyIPv6, b6, [2]uint16{}, DirectionIn)
	if !src.Equal(net.ParseIP("2001:db8::1")) || !dst.Equal(net.ParseIP("2001:db8::2")) {
		t.Errorf("v6 = %v -> %v", src, dst)
	}

	// An unknown family yields no addresses, so no filter matches it.
	src, dst, _, _ = decodeStateKey(0, wire, wp, DirectionIn)
	if src != nil || dst != nil {
		t.Errorf("unknown af = %v, %v; want nil", src, dst)
	}
}
