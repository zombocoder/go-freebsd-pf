package pf

import (
	"errors"
	"testing"
)

func TestBlockPolicyKernelMapping(t *testing.T) {
	// Values as pfctl's parse.y sets them for `block return*`.
	const (
		icmpDefault  = 0x0303 // (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT
		icmp6Default = 0x0104 // (ICMP6_DST_UNREACH << 8) | ICMP6_DST_UNREACH_NOPORT
	)
	tests := []struct {
		p     BlockPolicy
		flag  uint32
		icmp  uint16
		icmp6 uint16
	}{
		{BlockPolicyDrop, 0, 0, 0},
		{BlockPolicyReturn, 0x08, icmpDefault, icmp6Default},
		{BlockPolicyReturnRST, 0x01, 0, 0},
		{BlockPolicyReturnICMP, 0x04, icmpDefault, icmp6Default},
	}
	for _, tt := range tests {
		flag, icmp, icmp6 := blockPolicyToKernel(tt.p)
		if flag != tt.flag || icmp != tt.icmp || icmp6 != tt.icmp6 {
			t.Errorf("%v: got (%#x,%#x,%#x), want (%#x,%#x,%#x)",
				tt.p, flag, icmp, icmp6, tt.flag, tt.icmp, tt.icmp6)
		}
		// Unrelated rule_flag bits must not change the policy.
		if got := blockPolicyFromKernel(flag | 0x10 | 0x20000); got != tt.p {
			t.Errorf("%v: round trip got %v", tt.p, got)
		}
	}
}

func TestBlockPolicyFromKernelPrecedence(t *testing.T) {
	// pfctl's print_rule tests RETURN before RETURNRST before RETURNICMP.
	if got := blockPolicyFromKernel(0x08 | 0x01); got != BlockPolicyReturn {
		t.Errorf("got %v", got)
	}
	if got := blockPolicyFromKernel(0x01 | 0x04); got != BlockPolicyReturnRST {
		t.Errorf("got %v", got)
	}
}

func TestBlockPolicyString(t *testing.T) {
	want := map[BlockPolicy]string{
		BlockPolicyDrop: "drop", BlockPolicyReturn: "return",
		BlockPolicyReturnRST: "return-rst", BlockPolicyReturnICMP: "return-icmp",
		BlockPolicy(99): "unknown",
	}
	for p, s := range want {
		if p.String() != s {
			t.Errorf("%d: got %q want %q", p, p.String(), s)
		}
	}
}

func TestRtableMapping(t *testing.T) {
	if got := rtableToKernel(nil); got != -1 {
		t.Errorf("unset rtable must be -1, got %d", got)
	}
	zero, three := 0, 3
	if got := rtableToKernel(&zero); got != 0 {
		t.Errorf("explicit 0 must stay 0, got %d", got)
	}
	if got := rtableToKernel(&three); got != 3 {
		t.Errorf("got %d", got)
	}
	if got := rtableFromKernel(-1); got != nil {
		t.Errorf("-1 must read back as unset, got %d", *got)
	}
	if got := rtableFromKernel(0); got == nil || *got != 0 {
		t.Errorf("0 must read back as explicit 0")
	}
	if got := rtableFromKernel(5); got == nil || *got != 5 {
		t.Errorf("5 must read back as 5")
	}
}

func TestValidateBlockPolicyAndRtable(t *testing.T) {
	for _, a := range []Action{ActionPass, ActionMatch} {
		err := ValidateRule(Rule{Action: a, BlockPolicy: BlockPolicyReturn})
		if !errors.Is(err, ErrInvalidRule) {
			t.Errorf("action %v with BlockPolicy: got %v", a, err)
		}
	}
	for _, p := range []BlockPolicy{BlockPolicyDrop, BlockPolicyReturn, BlockPolicyReturnRST, BlockPolicyReturnICMP} {
		if err := ValidateRule(Rule{Action: ActionBlock, BlockPolicy: p, Protocol: ProtocolTCP}); err != nil {
			t.Errorf("block %v: %v", p, err)
		}
	}
	if err := ValidateRule(Rule{Action: ActionBlock, BlockPolicy: BlockPolicy(99)}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("unknown policy: got %v", err)
	}
	neg, zero := -1, 0
	if err := ValidateRule(Rule{Action: ActionPass, Rtable: &neg}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("negative rtable: got %v", err)
	}
	if err := ValidateRule(Rule{Action: ActionPass, Rtable: &zero}); err != nil {
		t.Errorf("rtable 0: %v", err)
	}
	big := 1 << 31
	if err := ValidateRule(Rule{Action: ActionPass, Rtable: &big}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("huge rtable: got %v", err)
	}
}
