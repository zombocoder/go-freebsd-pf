package pf

import (
	"errors"
	"net"
	"testing"
)

func invalid(t *testing.T, name string, r Rule) {
	t.Helper()
	if err := ValidateRule(r); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("%s: want ErrInvalidRule, got %v", name, err)
	}
}

func valid(t *testing.T, name string, r Rule) {
	t.Helper()
	if err := ValidateRule(r); err != nil {
		t.Errorf("%s: unexpected %v", name, err)
	}
}

func TestReturnRSTNeedsTCP(t *testing.T) {
	invalid(t, "rst any proto", Rule{Action: ActionBlock, BlockPolicy: BlockPolicyReturnRST})
	invalid(t, "rst udp", Rule{Action: ActionBlock, BlockPolicy: BlockPolicyReturnRST, Protocol: ProtocolUDP})
	valid(t, "rst tcp", Rule{Action: ActionBlock, BlockPolicy: BlockPolicyReturnRST, Protocol: ProtocolTCP})
	valid(t, "return any proto", Rule{Action: ActionBlock, BlockPolicy: BlockPolicyReturn})
}

func TestEffectiveAF(t *testing.T) {
	v4 := Address{IP: net.ParseIP("10.0.0.1")}
	_, n4, _ := net.ParseCIDR("10.1.0.0/16")
	v6 := Address{IP: net.ParseIP("fd00::1")}
	_, n6, _ := net.ParseCIDR("fd00::/64")

	tests := []struct {
		name string
		r    Rule
		want AddressFamily
		bad  bool
	}{
		{"none", Rule{}, AddressFamilyAny, false},
		{"src v4", Rule{Source: v4}, AddressFamilyIPv4, false},
		{"dst v4 net", Rule{Destination: Address{Network: n4}}, AddressFamilyIPv4, false},
		{"dst v6 net", Rule{Destination: Address{Network: n6}}, AddressFamilyIPv6, false},
		{"src v6", Rule{Source: v6}, AddressFamilyIPv6, false},
		{"explicit matches", Rule{AF: AddressFamilyIPv4, Source: v4}, AddressFamilyIPv4, false},
		{"explicit only", Rule{AF: AddressFamilyIPv6}, AddressFamilyIPv6, false},
		{"table keeps any", Rule{Source: Address{Table: "t"}}, AddressFamilyAny, false},
		{"any keeps any", Rule{Source: Address{Any: true}}, AddressFamilyAny, false},
		{"v4 addr, af6", Rule{AF: AddressFamilyIPv6, Source: v4}, 0, true},
		{"v6 addr, af4", Rule{AF: AddressFamilyIPv4, Destination: Address{Network: n6}}, 0, true},
		{"mixed", Rule{Source: v4, Destination: v6}, 0, true},
		{"table plus v6", Rule{Source: Address{Table: "t"}, Destination: v6}, AddressFamilyIPv6, false},
	}
	for _, tt := range tests {
		got, err := effectiveAF(tt.r)
		if tt.bad {
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("%s: want ErrInvalidRule, got %v", tt.name, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: got %v, %v want %v", tt.name, got, err, tt.want)
		}
		// ValidateRule must agree.
		valid(t, tt.name, tt.r)
	}
	for _, tt := range tests {
		if tt.bad {
			invalid(t, tt.name, tt.r)
		}
	}
}

func TestDynamicInterfaceAddress(t *testing.T) {
	valid(t, "self", Rule{Action: ActionPass, Destination: Address{Interface: "self"}})
	valid(t, "vtnet0 network", Rule{Action: ActionPass, Source: Address{Interface: "vtnet0", IfaceFlags: IfaceNetwork}})
	valid(t, "noalias+network", Rule{Action: ActionPass, Source: Address{Interface: "em0", IfaceFlags: IfaceNetwork | IfaceNoAlias}})
	invalid(t, "flags without name", Rule{Action: ActionPass, Source: Address{IfaceFlags: IfaceNetwork}})
	invalid(t, "two modes", Rule{Action: ActionPass, Source: Address{Interface: "em0", IfaceFlags: IfaceNetwork | IfacePeer}})
	invalid(t, "unknown flag bit", Rule{Action: ActionPass, Source: Address{Interface: "em0", IfaceFlags: 0x40}})
	invalid(t, "too long", Rule{Action: ActionPass, Source: Address{Interface: "abcdefghijklmnop"}})
	invalid(t, "digit first", Rule{Action: ActionPass, Source: Address{Interface: "0em"}})
	invalid(t, "colon", Rule{Action: ActionPass, Source: Address{Interface: "em0:network"}})
	invalid(t, "with ip", Rule{Action: ActionPass, Source: Address{Interface: "em0", IP: net.ParseIP("10.0.0.1")}})
	invalid(t, "with table", Rule{Action: ActionPass, Source: Address{Interface: "em0", Table: "t"}})
	invalid(t, "with any", Rule{Action: ActionPass, Source: Address{Interface: "em0", Any: true}})
	// A dynamic address says nothing about the family.
	if af, err := effectiveAF(Rule{Source: Address{Interface: "self"}}); err != nil || af != AddressFamilyAny {
		t.Errorf("dyn af: %v %v", af, err)
	}
}

func TestTCPFlags(t *testing.T) {
	if f := FlagsSA(); f.Check != TCPFlagSYN || f.Mask != TCPFlagSYN|TCPFlagACK {
		t.Errorf("FlagsSA = %+v", f)
	}
	valid(t, "S/SA tcp", Rule{Action: ActionPass, Protocol: ProtocolTCP, TCPFlags: FlagsSA()})
	valid(t, "none", Rule{Action: ActionPass})
	invalid(t, "any proto", Rule{Action: ActionPass, TCPFlags: FlagsSA()})
	invalid(t, "udp", Rule{Action: ActionPass, Protocol: ProtocolUDP, TCPFlags: FlagsSA()})
	invalid(t, "check not in mask", Rule{Action: ActionPass, Protocol: ProtocolTCP, TCPFlags: TCPFlags{Check: TCPFlagFIN, Mask: TCPFlagSYN}})
	invalid(t, "check without mask", Rule{Action: ActionPass, Protocol: ProtocolTCP, TCPFlags: TCPFlags{Check: TCPFlagSYN}})
}

func TestICMPTypeCode(t *testing.T) {
	ty, code := uint8(8), uint8(0)
	valid(t, "echo", Rule{Action: ActionPass, Protocol: ProtocolICMP, ICMPType: &ty})
	valid(t, "type+code", Rule{Action: ActionPass, Protocol: ProtocolICMP, ICMPType: &ty, ICMPCode: &code})
	valid(t, "icmp6", Rule{Action: ActionPass, Protocol: ProtocolICMPv6, ICMPType: &ty})
	invalid(t, "code only", Rule{Action: ActionPass, Protocol: ProtocolICMP, ICMPCode: &code})
	invalid(t, "tcp", Rule{Action: ActionPass, Protocol: ProtocolTCP, ICMPType: &ty})
	invalid(t, "any proto", Rule{Action: ActionPass, ICMPType: &ty})
	// kernel stores type+1 and code+1 in a byte
	big := uint8(255)
	invalid(t, "type 255", Rule{Action: ActionPass, Protocol: ProtocolICMP, ICMPType: &big})
}

func TestICMPAddressFamily(t *testing.T) {
	ty := uint8(8)
	cases := []struct {
		name string
		r    Rule
		want AddressFamily
		bad  bool
	}{
		{"icmp infers inet", Rule{Protocol: ProtocolICMP, ICMPType: &ty}, AddressFamilyIPv4, false},
		{"icmp6 infers inet6", Rule{Protocol: ProtocolICMPv6}, AddressFamilyIPv6, false},
		{"icmp explicit inet", Rule{Protocol: ProtocolICMP, AF: AddressFamilyIPv4}, AddressFamilyIPv4, false},
		{"icmp with inet6", Rule{Protocol: ProtocolICMP, AF: AddressFamilyIPv6}, 0, true},
		{"icmp6 with inet", Rule{Protocol: ProtocolICMPv6, AF: AddressFamilyIPv4}, 0, true},
		{"icmp with v6 addr", Rule{Protocol: ProtocolICMP, Source: Address{IP: net.ParseIP("fd00::1")}}, 0, true},
		{"icmp6 with v4 addr", Rule{Protocol: ProtocolICMPv6, Destination: Address{IP: net.ParseIP("10.0.0.1")}}, 0, true},
		{"tcp stays open", Rule{Protocol: ProtocolTCP}, AddressFamilyAny, false},
		{"v4-mapped v6 is v4", Rule{Source: Address{IP: net.ParseIP("::ffff:10.0.0.1")}}, AddressFamilyIPv4, false},
		{"v4-mapped with af6", Rule{AF: AddressFamilyIPv6, Source: Address{IP: net.ParseIP("::ffff:10.0.0.1")}}, 0, true},
	}
	for _, c := range cases {
		got, err := effectiveAF(c.r)
		if c.bad {
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("%s: want ErrInvalidRule, got %v", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v want %v", c.name, got, err, c.want)
		}
	}
}

func TestProtocolICMPv6String(t *testing.T) {
	if s := ProtocolICMPv6.String(); s != "ipv6-icmp" {
		t.Errorf("got %q", s)
	}
}

func TestICMPWireValues(t *testing.T) {
	zero, five := uint8(0), uint8(5)
	if got := icmpTypeCodeToKernel(nil, nil); got != [2]uint8{0, 0} {
		t.Errorf("unset: %v", got)
	}
	if got := icmpTypeCodeToKernel(&zero, nil); got != [2]uint8{1, 0} {
		t.Errorf("type 0: %v", got)
	}
	if got := icmpTypeCodeToKernel(&five, &zero); got != [2]uint8{6, 1} {
		t.Errorf("code 0: %v", got)
	}
	ty, code := icmpTypeCodeFromKernel(6, 1)
	if ty == nil || *ty != 5 || code == nil || *code != 0 {
		t.Errorf("code 0 read back: %v %v", ty, code)
	}
	ty, code = icmpTypeCodeFromKernel(1, 0)
	if ty == nil || *ty != 0 || code != nil {
		t.Errorf("type 0 read back: %v %v", ty, code)
	}
	if ty, code = icmpTypeCodeFromKernel(0, 0); ty != nil || code != nil {
		t.Errorf("unset read back")
	}
}

func TestSameAnchorCall(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"microvm-runner/*", "microvm-runner/*", true},
		{"/microvm-runner/*", "microvm-runner/*", true},
		{"microvm-runner/*", "/microvm-runner/*", true},
		{"/microvm-runner/*", "/microvm-runner/*", true},
		{"microvm-runner", "microvm-runner/*", false},
		{"//microvm-runner/*", "microvm-runner/*", false},
		{"", "", false},
		{"/", "", false},
	}
	for _, c := range cases {
		if got := sameAnchorCall(c.a, c.b); got != c.want {
			t.Errorf("sameAnchorCall(%q,%q) = %v", c.a, c.b, got)
		}
	}
}
