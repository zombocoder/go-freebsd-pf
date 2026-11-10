package pf

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

// matchesFilter checks if a state matches the given filter criteria.
//
// The interface criterion follows the kernel's DIOCKILLSTATES/DIOCCLRSTATES
// (pf_killstates_row, pf_clear_states): a floating state (state-policy
// floating, the default) is attached to the pseudo-interface "all" and is
// matched by the interface it was created on (OrigInterface) only; an
// if-bound state is matched by the interface it is bound to. So ListStates
// lists exactly the states KillStates with the same filter would remove.
func matchesFilter(s State, f StateFilter) bool {
	if f.Interface != "" && stateKillInterface(s) != f.Interface {
		return false
	}
	src, dst := s.Source, s.Destination
	if f.NAT {
		src, dst = s.natSource, s.natDestination
	}
	if f.Source != nil && !f.Source.Contains(src) {
		return false
	}
	if f.Destination != nil && !f.Destination.Contains(dst) {
		return false
	}
	return true
}

// stateKillInterface is the interface name the kernel compares when
// killing or clearing states by interface.
func stateKillInterface(s State) string {
	if s.Interface == "all" {
		return s.OrigInterface
	}
	return s.Interface
}

// orientWireKey turns the wire-side state key into initiator/responder
// order. PF stores keys in inbound orientation: for an inbound state slot
// 0 is the initiator, for an outbound state slot 1 is (see pfctl's
// print_state, which prints addr[1] -> addr[0] for "out").
func orientWireKey(dir Direction, addr [2]net.IP, port [2]uint16) (src, dst net.IP, sport, dport uint16) {
	if dir == DirectionOut {
		return addr[1], addr[0], port[1], port[0]
	}
	return addr[0], addr[1], port[0], port[1]
}

// decodeStateKey reads the two addresses (raw pf_addr slots, 16 bytes each)
// and ports (host order) of a pf_state_key_export as initiator/responder.
// af is the family of the state as exported: pf_state_export carries only
// the wire family, which is what both keys are read with (see
// StateFilter.NAT for the af-to consequence). An unknown family yields nil
// addresses.
func decodeStateKey(af AddressFamily, raw [32]byte, ports [2]uint16, dir Direction) (src, dst net.IP, sport, dport uint16) {
	var addrs [2]net.IP
	switch af {
	case AddressFamilyIPv4:
		addrs[0] = net.IPv4(raw[0], raw[1], raw[2], raw[3])
		addrs[1] = net.IPv4(raw[16], raw[17], raw[18], raw[19])
	case AddressFamilyIPv6:
		addrs[0] = append(net.IP(nil), raw[0:16]...)
		addrs[1] = append(net.IP(nil), raw[16:32]...)
	}
	return orientWireKey(dir, addrs, ports)
}

// ntohl converts a 32-bit value the kernel stored in network byte order
// (htonl) to host order.
func ntohl(v uint32) uint32 {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return binary.BigEndian.Uint32(b[:])
}

// be64toh converts a 64-bit value stored big-endian (htobe64) to host order.
func be64toh(v uint64) uint64 {
	var b [8]byte
	binary.NativeEndian.PutUint64(b[:], v)
	return binary.BigEndian.Uint64(b[:])
}

// DIOCGETSTATESV2 buffer sizing.
//
// The kernel (pf_ioctl.c on 13.x, 14.x and 15.x alike) copies whole hash
// rows and, at the first row that does not fit, stops and returns success
// with ps_len set to the bytes written. There is no "buffer too small"
// signal, so completeness is decided by statesNext: a reply counts as
// complete only when it leaves statesSlack entries of room and a second
// pass returns the same size.
const (
	statesSlack = 16
	// statesMaxBytes caps the buffer (about 700k states); ps_len is a C int.
	statesMaxBytes = 256 << 20
	// statesMaxPasses bounds the retries before ListStates gives up.
	statesMaxPasses = 10
)

// statesMaxLen is the largest buffer used: statesMaxBytes (and MaxInt32)
// rounded down to a whole number of entries.
func statesMaxLen(entry int) int {
	m := statesMaxBytes
	if m > math.MaxInt32 {
		m = math.MaxInt32
	}
	return m - m%entry
}

// statesBufLen returns the buffer size for DIOCGETSTATESV2 given the
// kernel's size probe (bytes): 25% more entries than probed plus slack,
// since states keep being created between the probe and the copy. The
// result is a multiple of entry and at most statesMaxLen.
func statesBufLen(probe, entry int) int {
	if probe < 0 {
		probe = 0
	}
	maxLen := statesMaxLen(entry)
	n := probe / entry
	if n > maxLen/entry {
		return maxLen
	}
	l := (n*5/4 + statesSlack) * entry
	if l > maxLen {
		return maxLen
	}
	return l
}

// statesNext decides what to do after a DIOCGETSTATESV2 pass that wrote
// returned bytes into a bufLen buffer. prev is the size returned by the
// previous pass if that pass had room to spare, or -1. It reports whether
// the listing is complete, else the buffer size for the next pass, or an
// error for a malformed reply or a table that cannot fit.
func statesNext(prev, returned, bufLen, entry int) (done bool, next int, err error) {
	if returned < 0 || returned > bufLen || returned%entry != 0 {
		return false, 0, fmt.Errorf("%w: kernel returned %d bytes for a %d-byte buffer", ErrInvalidArgument, returned, bufLen)
	}
	maxLen := statesMaxLen(entry)
	if bufLen-returned >= statesSlack*entry {
		if prev == returned {
			return true, 0, nil
		}
		// Room to spare but not confirmed yet: repeat (same or larger size).
		return false, max(bufLen, statesBufLen(returned, entry)), nil
	}
	if bufLen >= maxLen {
		return false, 0, fmt.Errorf("%w: more than %d bytes of states", ErrStatesIncomplete, maxLen)
	}
	return false, min(max(bufLen*2, statesBufLen(returned, entry)), maxLen), nil
}
