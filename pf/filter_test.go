package pf

import (
	"encoding/binary"
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
