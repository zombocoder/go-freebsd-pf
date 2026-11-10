//go:build freebsd && cgo

package pf

/*
#cgo freebsd CFLAGS: -D__BSD_VISIBLE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <string.h>
*/
import "C"
import (
	"net"
	"strings"
	"time"
	"unsafe"
)

// The ruleset-selecting actions in validate.go must match the header; a
// mismatch makes one of these constant indexes out of range at compile time.
var (
	_ = [1]int{}[C.PF_PASS-pfActPass]
	_ = [1]int{}[C.PF_SCRUB-pfActScrub]
	_ = [1]int{}[C.PF_NAT-pfActNAT]
	_ = [1]int{}[C.PF_BINAT-pfActBINAT]
	_ = [1]int{}[C.PF_RDR-pfActRDR]
)

// ruleToC converts a Go Rule to C pfioc_rule struct.
func ruleToC(r Rule, anchor string) C.struct_pfioc_rule {
	var pr C.struct_pfioc_rule
	C.memset(unsafe.Pointer(&pr), 0, C.sizeof_struct_pfioc_rule)

	if anchor != "" {
		copyStringToC(&pr.anchor[0], anchor, C.MAXPATHLEN)
	}

	rule := &pr.rule

	// Action
	switch r.Action {
	case ActionPass:
		rule.action = C.PF_PASS
	case ActionBlock:
		rule.action = C.PF_DROP
	case ActionMatch:
		rule.action = C.PF_MATCH
	}

	// Direction
	switch r.Direction {
	case DirectionIn:
		rule.direction = C.PF_IN
	case DirectionOut:
		rule.direction = C.PF_OUT
	case DirectionAny:
		rule.direction = C.PF_INOUT
	}

	// Interface
	if r.Interface != "" {
		copyStringToC(&rule.ifname[0], r.Interface, C.IFNAMSIZ)
	}

	// Protocol
	rule.proto = C.u_int8_t(r.Protocol)

	// Address family
	rule.af = C.sa_family_t(r.AF)

	// Source address
	setRuleAddr(&rule.src, r.Source, r.SourcePort)

	// Destination address
	setRuleAddr(&rule.dst, r.Destination, r.DestinationPort)

	// Flags
	if r.Quick {
		rule.quick = 1
	}
	if r.Log {
		rule.log = C.PF_LOG
	}
	if r.KeepState {
		rule.keep_state = C.PF_STATE_NORMAL
	}

	// Label
	if r.Label != "" {
		copyStringToC(&rule.label[0], r.Label, C.PF_RULE_LABEL_SIZE)
	}

	return pr
}

// setRuleAddr configures a pf_rule_addr from Go types.
func setRuleAddr(ra *C.struct_pf_rule_addr, addr Address, port PortMatcher) {
	if addr.Negate {
		ra.neg = 1
	}

	if addr.Any {
		// ADDRMASK with zeros = any
		setAddrWrapAddrmask(&ra.addr, nil, nil)
	} else if addr.Table != "" {
		setAddrWrapTable(&ra.addr, addr.Table)
	} else if addr.Network != nil {
		ip := addr.Network.IP
		mask := addr.Network.Mask
		addrBytes, maskBytes := ipAndMaskToBytes(ip, mask)
		setAddrWrapAddrmask(&ra.addr, addrBytes, maskBytes)
	} else if addr.IP != nil {
		addrBytes, maskBytes := singleHostBytes(addr.IP)
		setAddrWrapAddrmask(&ra.addr, addrBytes, maskBytes)
	}

	// Port
	ra.port_op = C.u_int8_t(port.Operator)
	ra.port[0] = htons(port.From)
	ra.port[1] = htons(port.To)
}

func ipAndMaskToBytes(ip net.IP, mask net.IPMask) (addr, msk []byte) {
	if ip4 := ip.To4(); ip4 != nil {
		addr = make([]byte, 16)
		msk = make([]byte, 16)
		copy(addr, ip4)
		if len(mask) == 4 {
			copy(msk, mask)
		} else if len(mask) >= 16 {
			copy(msk, mask[12:16])
		}
	} else {
		addr = make([]byte, 16)
		msk = make([]byte, 16)
		copy(addr, ip.To16())
		copy(msk, mask)
	}
	return
}

func singleHostBytes(ip net.IP) (addr, mask []byte) {
	addr = make([]byte, 16)
	mask = make([]byte, 16)
	if ip4 := ip.To4(); ip4 != nil {
		copy(addr, ip4)
		mask[0], mask[1], mask[2], mask[3] = 0xff, 0xff, 0xff, 0xff
	} else {
		copy(addr, ip.To16())
		for i := 0; i < 16; i++ {
			mask[i] = 0xff
		}
	}
	return
}

// ruleFromC converts a C pfioc_rule to a Go Rule.
func ruleFromC(pr *C.struct_pfioc_rule) Rule {
	rule := &pr.rule
	r := Rule{
		Nr: uint32(rule.nr),
	}

	switch rule.action {
	case C.PF_PASS:
		r.Action = ActionPass
	case C.PF_DROP:
		r.Action = ActionBlock
	case C.PF_MATCH:
		r.Action = ActionMatch
	}

	switch rule.direction {
	case C.PF_IN:
		r.Direction = DirectionIn
	case C.PF_OUT:
		r.Direction = DirectionOut
	default:
		r.Direction = DirectionAny
	}

	r.Interface = strings.TrimRight(C.GoString(&rule.ifname[0]), "\x00")
	r.Protocol = Protocol(rule.proto)
	r.AF = AddressFamily(rule.af)
	r.Source = addrFromC(&rule.src)
	r.SourcePort = portFromC(&rule.src)
	r.Destination = addrFromC(&rule.dst)
	r.DestinationPort = portFromC(&rule.dst)
	r.Quick = rule.quick != 0
	r.Log = rule.log != 0
	r.KeepState = rule.keep_state != 0
	r.Label = strings.TrimRight(C.GoString(&rule.label[0]), "\x00")
	r.Anchor = strings.TrimRight(C.GoString(&pr.anchor[0]), "\x00")

	// Per-rule statistics
	r.Evaluations = uint64(rule.evaluations)
	r.Packets[0] = uint64(rule.packets[0])
	r.Packets[1] = uint64(rule.packets[1])
	r.Bytes[0] = uint64(rule.bytes[0])
	r.Bytes[1] = uint64(rule.bytes[1])

	return r
}

// addrFromC converts a C pf_rule_addr to a Go Address.
func addrFromC(ra *C.struct_pf_rule_addr) Address {
	addr := Address{
		Negate: ra.neg != 0,
	}

	switch ra.addr._type {
	case C.PF_ADDR_ADDRMASK:
		raw := getAddrWrapAddr(&ra.addr, 16)
		mask := getAddrWrapMask(&ra.addr, 16)

		allZero := true
		for _, b := range raw {
			if b != 0 {
				allZero = false
				break
			}
		}
		maskAllZero := true
		for _, b := range mask {
			if b != 0 {
				maskAllZero = false
				break
			}
		}

		if allZero && maskAllZero {
			addr.Any = true
		} else {
			addr.IP = bytesToIP(raw)
			if !maskAllZero {
				addr.Network = &net.IPNet{
					IP:   addr.IP,
					Mask: bytesToMask(mask),
				}
			}
		}
	case C.PF_ADDR_TABLE:
		addr.Table = getAddrWrapTblname(&ra.addr)
	}

	return addr
}

func bytesToIP(raw []byte) net.IP {
	isV4 := true
	for i := 4; i < 16; i++ {
		if raw[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		return net.IPv4(raw[0], raw[1], raw[2], raw[3])
	}
	ip := make(net.IP, 16)
	copy(ip, raw)
	return ip
}

func bytesToMask(raw []byte) net.IPMask {
	isV4 := true
	for i := 4; i < 16; i++ {
		if raw[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		return net.IPMask([]byte{raw[0], raw[1], raw[2], raw[3]})
	}
	mask := make(net.IPMask, 16)
	copy(mask, raw)
	return mask
}

// portFromC extracts port info from a C pf_rule_addr.
func portFromC(ra *C.struct_pf_rule_addr) PortMatcher {
	return PortMatcher{
		Operator: PortOperator(ra.port_op),
		From:     ntohs(ra.port[0]),
		To:       ntohs(ra.port[1]),
	}
}

// Byte order helpers — PF stores ports in network byte order.
func htons(v uint16) C.u_int16_t {
	return C.u_int16_t((v >> 8) | (v << 8))
}

func ntohs(v C.u_int16_t) uint16 {
	u := uint16(v)
	return (u >> 8) | (u << 8)
}

// goTable converts a C pfr_table to a Go Table.
func goTable(ct *C.struct_pfr_table) Table {
	return Table{
		Name:   strings.TrimRight(C.GoString(&ct.pfrt_name[0]), "\x00"),
		Anchor: strings.TrimRight(C.GoString(&ct.pfrt_anchor[0]), "\x00"),
		Flags:  TableFlags(ct.pfrt_flags),
	}
}

// goTableAddress converts a C pfr_addr to a Go TableAddress.
func goTableAddress(ca *C.struct_pfr_addr) TableAddress {
	ta := TableAddress{
		Negate: ca.pfra_not != 0,
	}

	prefixLen := int(ca.pfra_net)

	switch ca.pfra_af {
	case C.AF_INET:
		raw := (*[4]byte)(unsafe.Pointer(&ca.pfra_u))
		ip := net.IPv4(raw[0], raw[1], raw[2], raw[3])
		if prefixLen == 32 {
			ta.IP = ip
		} else {
			ta.Network = &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(prefixLen, 32),
			}
		}
	case C.AF_INET6:
		raw := (*[16]byte)(unsafe.Pointer(&ca.pfra_u))
		ip := make(net.IP, 16)
		copy(ip, raw[:])
		if prefixLen == 128 {
			ta.IP = ip
		} else {
			ta.Network = &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(prefixLen, 128),
			}
		}
	}

	return ta
}

// cPfrAddr converts a Go TableAddress to a C pfr_addr.
func cPfrAddr(ta TableAddress) C.struct_pfr_addr {
	var ca C.struct_pfr_addr
	C.memset(unsafe.Pointer(&ca), 0, C.sizeof_struct_pfr_addr)

	if ta.Negate {
		ca.pfra_not = 1
	}

	if ta.Network != nil {
		ip := ta.Network.IP
		ones, _ := ta.Network.Mask.Size()
		if ip4 := ip.To4(); ip4 != nil {
			ca.pfra_af = C.AF_INET
			ca.pfra_net = C.u_int8_t(ones)
			dst := (*[4]byte)(unsafe.Pointer(&ca.pfra_u))
			copy(dst[:], ip4)
		} else {
			ca.pfra_af = C.AF_INET6
			ca.pfra_net = C.u_int8_t(ones)
			dst := (*[16]byte)(unsafe.Pointer(&ca.pfra_u))
			copy(dst[:], ip.To16())
		}
	} else if ta.IP != nil {
		if ip4 := ta.IP.To4(); ip4 != nil {
			ca.pfra_af = C.AF_INET
			ca.pfra_net = 32
			dst := (*[4]byte)(unsafe.Pointer(&ca.pfra_u))
			copy(dst[:], ip4)
		} else {
			ca.pfra_af = C.AF_INET6
			ca.pfra_net = 128
			dst := (*[16]byte)(unsafe.Pointer(&ca.pfra_u))
			copy(dst[:], ta.IP.To16())
		}
	}

	return ca
}

// stateFromC converts a C pf_state_export to a Go State.
func stateFromC(cs *C.struct_pf_state_export) State {
	s := State{
		ID:            be64toh(uint64(cs.id)),
		CreatorID:     ntohl(uint32(cs.creatorid)),
		Interface:     strings.TrimRight(C.GoString(&cs.ifname[0]), "\x00"),
		OrigInterface: strings.TrimRight(C.GoString(&cs.orig_ifname[0]), "\x00"),
		Protocol:      Protocol(cs.proto),
		AF:            AddressFamily(cs.af),
		// pf_state_export(): id, creatorid, creation and expire are
		// stored in network byte order.
		Creation: time.Duration(ntohl(uint32(cs.creation))) * time.Second,
		Expire:   time.Duration(ntohl(uint32(cs.expire))) * time.Second,
	}

	switch cs.direction {
	case C.PF_IN:
		s.Direction = DirectionIn
	case C.PF_OUT:
		s.Direction = DirectionOut
	default:
		s.Direction = DirectionAny
	}

	// Extract source/dest from key[PF_SK_WIRE]
	wireKey := &cs.key[C.PF_SK_WIRE]

	// pf_state_key_export has addr[2] (pf_addr) and port[2]
	// Access through raw bytes since cgo represents unions as byte arrays
	addrBytes := (*[32]byte)(unsafe.Pointer(&wireKey.addr[0]))
	var addrs [2]net.IP
	switch cs.af {
	case C.AF_INET:
		addrs[0] = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		addrs[1] = net.IPv4(addrBytes[16], addrBytes[17], addrBytes[18], addrBytes[19])
	case C.AF_INET6:
		addrs[0] = make(net.IP, 16)
		copy(addrs[0], addrBytes[0:16])
		addrs[1] = make(net.IP, 16)
		copy(addrs[1], addrBytes[16:32])
	}
	ports := [2]uint16{
		ntohs(C.u_int16_t(wireKey.port[0])),
		ntohs(C.u_int16_t(wireKey.port[1])),
	}
	s.Source, s.Destination, s.SourcePort, s.DestPort = orientWireKey(s.Direction, addrs, ports)

	s.Packets[0] = uint64(cs.packets[0])
	s.Packets[1] = uint64(cs.packets[1])
	s.Bytes[0] = uint64(cs.bytes[0])
	s.Bytes[1] = uint64(cs.bytes[1])

	return s
}

// cStateKill converts a StateFilter to a C pfioc_state_kill.
func cStateKill(f StateFilter) C.struct_pfioc_state_kill {
	var psk C.struct_pfioc_state_kill
	C.memset(unsafe.Pointer(&psk), 0, C.sizeof_struct_pfioc_state_kill)

	if f.Interface != "" {
		copyStringToC(&psk.psk_ifname[0], f.Interface, C.IFNAMSIZ)
	}

	if f.Label != "" {
		copyStringToC(&psk.psk_label[0], f.Label, C.PF_RULE_LABEL_SIZE)
	}

	if f.Source != nil {
		psk.psk_af = afFromNet(f.Source.IP)
		setStateAddr(&psk.psk_src, f.Source)
	}

	if f.Destination != nil {
		if psk.psk_af == 0 {
			psk.psk_af = afFromNet(f.Destination.IP)
		}
		setStateAddr(&psk.psk_dst, f.Destination)
	}

	return psk
}

func afFromNet(ip net.IP) C.sa_family_t {
	if ip.To4() != nil {
		return C.AF_INET
	}
	return C.AF_INET6
}

func setStateAddr(ra *C.struct_pf_rule_addr, cidr *net.IPNet) {
	addrBytes, maskBytes := ipAndMaskToBytes(cidr.IP, cidr.Mask)
	setAddrWrapAddrmask(&ra.addr, addrBytes, maskBytes)
}
