package pf

import (
	"encoding/binary"
	"net"
)

// matchesFilter checks if a state matches the given filter criteria.
//
// The interface criterion follows the kernel's DIOCKILLSTATES/DIOCCLRSTATES
// rule: a floating state (state-policy floating, the default) is attached
// to the pseudo-interface "all", so it is matched by the interface it was
// created on (OrigInterface) as well.
func matchesFilter(s State, f StateFilter) bool {
	if f.Interface != "" && s.Interface != f.Interface && s.OrigInterface != f.Interface {
		return false
	}
	if f.Source != nil && !f.Source.Contains(s.Source) {
		return false
	}
	if f.Destination != nil && !f.Destination.Contains(s.Destination) {
		return false
	}
	return true
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
