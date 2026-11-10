package pf

import "fmt"

// BlockPolicy is the policy of a block rule: what PF does with a blocked
// packet. The zero value is BlockPolicyDrop, PF's default.
type BlockPolicy uint8

const (
	BlockPolicyDrop       BlockPolicy = iota // block drop: silently discard
	BlockPolicyReturn                        // block return: RST for TCP, ICMP unreachable otherwise
	BlockPolicyReturnRST                     // block return-rst: TCP RST only
	BlockPolicyReturnICMP                    // block return-icmp: ICMP/ICMPv6 unreachable (port unreachable)
)

func (p BlockPolicy) String() string {
	switch p {
	case BlockPolicyDrop:
		return "drop"
	case BlockPolicyReturn:
		return "return"
	case BlockPolicyReturnRST:
		return "return-rst"
	case BlockPolicyReturnICMP:
		return "return-icmp"
	default:
		return "unknown"
	}
}

// rule_flag bits from <netpfil/pf/pf.h>; the cgo build checks them against
// the header at compile time.
const (
	pfRuleReturnRST  = 0x00000001 // PFRULE_RETURNRST
	pfRuleReturnICMP = 0x00000004 // PFRULE_RETURNICMP
	pfRuleReturn     = 0x00000008 // PFRULE_RETURN
)

// The ICMP codes pfctl's parse.y uses for a bare `return`/`return-icmp`:
// (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT and
// (ICMP6_DST_UNREACH << 8) | ICMP6_DST_UNREACH_NOPORT.
const (
	returnICMPDefault  = 0x0303
	returnICMP6Default = 0x0104
)

// blockPolicyToKernel returns the rule_flag bits, return_icmp and
// return_icmp6 that pfctl sets for `block <policy>`. return-rst keeps the
// TTL (return_ttl) at 0, as a bare `block return-rst` does.
func blockPolicyToKernel(p BlockPolicy) (flag uint32, icmp, icmp6 uint16) {
	switch p {
	case BlockPolicyReturn:
		return pfRuleReturn, returnICMPDefault, returnICMP6Default
	case BlockPolicyReturnRST:
		return pfRuleReturnRST, 0, 0
	case BlockPolicyReturnICMP:
		return pfRuleReturnICMP, returnICMPDefault, returnICMP6Default
	}
	return 0, 0, 0
}

// blockPolicyFromKernel reads the policy from rule_flag in the order
// pfctl's print_rule tests it. Other rule_flag bits are ignored.
func blockPolicyFromKernel(flag uint32) BlockPolicy {
	switch {
	case flag&pfRuleReturn != 0:
		return BlockPolicyReturn
	case flag&pfRuleReturnRST != 0:
		return BlockPolicyReturnRST
	case flag&pfRuleReturnICMP != 0:
		return BlockPolicyReturnICMP
	}
	return BlockPolicyDrop
}

// rtableToKernel returns the rtableid for a Rule.Rtable. nil is -1, which is
// what pfctl writes when a rule has no rtable option; 0 would pin the rule
// to routing table 0 and show as `rtable 0`.
func rtableToKernel(rt *int) int32 {
	if rt == nil {
		return -1
	}
	return int32(*rt)
}

// rtableFromKernel is the inverse of rtableToKernel.
func rtableFromKernel(id int32) *int {
	if id == -1 {
		return nil
	}
	v := int(id)
	return &v
}

func validateBlockPolicy(r Rule) error {
	if r.BlockPolicy > BlockPolicyReturnICMP {
		return fmt.Errorf("%w: invalid block policy %d", ErrInvalidRule, r.BlockPolicy)
	}
	if r.BlockPolicy != BlockPolicyDrop && r.Action != ActionBlock {
		return fmt.Errorf("%w: block policy %v only applies to block rules", ErrInvalidRule, r.BlockPolicy)
	}
	// pfctl: "return-rst can only be applied to TCP rules".
	if r.BlockPolicy == BlockPolicyReturnRST && r.Protocol != ProtocolTCP {
		return fmt.Errorf("%w: return-rst can only be applied to TCP rules", ErrInvalidRule)
	}
	return nil
}

func validateRtable(rt *int) error {
	if rt == nil {
		return nil
	}
	if *rt < 0 || *rt > 1<<31-1 {
		return fmt.Errorf("%w: rtable %d out of range", ErrInvalidRule, *rt)
	}
	return nil
}
