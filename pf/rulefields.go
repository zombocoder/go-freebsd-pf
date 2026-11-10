package pf

import (
	"fmt"
	"net"
	"strings"
)

// addrFamily returns the family an Address pins the rule to, or Any.
func addrFamily(a Address) AddressFamily {
	var ip net.IP
	switch {
	case a.Network != nil:
		ip = a.Network.IP
	case a.IP != nil:
		ip = a.IP
	default:
		return AddressFamilyAny
	}
	if ip.To4() != nil {
		return AddressFamilyIPv4
	}
	return AddressFamilyIPv6
}

// effectiveAF returns the address family the rule is added with. pfctl
// always sets af when an address is given; so does this: an AF of Any is
// inferred from the source and destination addresses. An explicit AF that
// contradicts an address, or a v4 address mixed with a v6 one, is an
// ErrInvalidRule. Tables, any and dynamic interface addresses leave the
// family open.
func effectiveAF(r Rule) (AddressFamily, error) {
	af := r.AF
	for _, p := range []struct {
		name string
		a    Address
	}{{"source", r.Source}, {"destination", r.Destination}} {
		f := addrFamily(p.a)
		if f == AddressFamilyAny {
			continue
		}
		if af == AddressFamilyAny {
			af = f
		} else if af != f {
			return 0, fmt.Errorf("%w: %s address family does not match the rule's (%s)", ErrInvalidRule, p.name, afName(af))
		}
	}
	// pfctl derives the family from the protocol too: icmp is inet,
	// ipv6-icmp is inet6. Anything else contradicts the protocol.
	var pf AddressFamily
	switch r.Protocol {
	case ProtocolICMP:
		pf = AddressFamilyIPv4
	case ProtocolICMPv6:
		pf = AddressFamilyIPv6
	}
	if pf != AddressFamilyAny {
		if af != AddressFamilyAny && af != pf {
			return 0, fmt.Errorf("%w: protocol %v needs %s, not %s", ErrInvalidRule, r.Protocol, afName(pf), afName(af))
		}
		af = pf
	}
	return af, nil
}

// icmpTypeCodeToKernel returns {type, code} as pf stores them: the value+1,
// 0 meaning any.
func icmpTypeCodeToKernel(ty, code *uint8) (out [2]uint8) {
	if ty != nil {
		out[0] = *ty + 1
		if code != nil {
			out[1] = *code + 1
		}
	}
	return out
}

func icmpTypeCodeFromKernel(ty, code uint8) (t, c *uint8) {
	if ty == 0 {
		return nil, nil
	}
	v := ty - 1
	t = &v
	if code != 0 {
		w := code - 1
		c = &w
	}
	return t, c
}

// sameAnchorCall compares two anchor-call paths, ignoring one leading "/"
// (`anchor "/x/*"` and `anchor "x/*"` are the same call in the main
// ruleset). "x" and "x/*" are different calls.
func sameAnchorCall(a, b string) bool {
	a, b = strings.TrimPrefix(a, "/"), strings.TrimPrefix(b, "/")
	return a != "" && a == b
}

func afName(af AddressFamily) string {
	if af == AddressFamilyIPv4 {
		return "inet"
	}
	return "inet6"
}

func validateDynAddress(a Address) error {
	if a.Interface == "" {
		return fmt.Errorf("interface flags without an interface name")
	}
	if a.Any || a.IP != nil || a.Network != nil || a.Table != "" {
		return fmt.Errorf("interface address excludes any, ip, network and table")
	}
	n := a.Interface
	if len(n) >= ifNameSize {
		return fmt.Errorf("interface name too long (max %d chars)", ifNameSize-1)
	}
	for i, c := range n {
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		other := (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'
		if !alpha && !(i > 0 && other) {
			return fmt.Errorf("invalid interface name %q", n)
		}
	}
	const all = IfaceNetwork | IfaceBroadcast | IfacePeer | IfaceNoAlias
	if a.IfaceFlags&^all != 0 {
		return fmt.Errorf("unknown interface flags %#x", uint8(a.IfaceFlags))
	}
	modes := a.IfaceFlags & (IfaceNetwork | IfaceBroadcast | IfacePeer)
	if modes&(modes-1) != 0 {
		return fmt.Errorf("illegal combination of interface modifiers")
	}
	return nil
}

func validateTCPFlags(r Rule) error {
	f := r.TCPFlags
	if f == (TCPFlags{}) {
		return nil
	}
	if r.Protocol != ProtocolTCP {
		return fmt.Errorf("%w: TCP flags only apply to tcp", ErrInvalidRule)
	}
	if f.Check&^f.Mask != 0 {
		return fmt.Errorf("%w: TCP flags check %#x is not a subset of mask %#x", ErrInvalidRule, f.Check, f.Mask)
	}
	return nil
}

func validateICMP(r Rule) error {
	if r.ICMPType == nil && r.ICMPCode == nil {
		return nil
	}
	if r.Protocol != ProtocolICMP && r.Protocol != ProtocolICMPv6 {
		return fmt.Errorf("%w: icmp type/code only apply to icmp and icmp6", ErrInvalidRule)
	}
	if r.ICMPType == nil {
		return fmt.Errorf("%w: icmp code needs an icmp type", ErrInvalidRule)
	}
	// pf stores type+1 and code+1 in a byte.
	if *r.ICMPType == 255 || (r.ICMPCode != nil && *r.ICMPCode == 255) {
		return fmt.Errorf("%w: icmp type/code 255 is not representable", ErrInvalidRule)
	}
	return nil
}
