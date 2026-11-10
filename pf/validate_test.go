package pf

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestValidateRule(t *testing.T) {
	t.Run("valid minimal rule", func(t *testing.T) {
		r := Rule{Action: ActionPass}
		if err := ValidateRule(r); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("valid full rule", func(t *testing.T) {
		_, net4, _ := net.ParseCIDR("10.0.0.0/24")
		r := Rule{
			Action:    ActionBlock,
			Direction: DirectionIn,
			Interface: "em0",
			Protocol:  ProtocolTCP,
			Source:    Address{Network: net4},
			Destination: Address{
				IP: net.ParseIP("192.168.1.1"),
			},
			DestinationPort: PortMatcher{Operator: PortOpEq, From: 80},
			Quick:           true,
			Log:             true,
			KeepState:       true,
			Label:           "web_traffic",
		}
		if err := ValidateRule(r); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("invalid action", func(t *testing.T) {
		r := Rule{Action: Action(99)}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for invalid action")
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("expected ErrInvalidRule, got %v", err)
		}
	})

	t.Run("label too long", func(t *testing.T) {
		r := Rule{
			Action: ActionPass,
			Label:  strings.Repeat("x", 64),
		}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for long label")
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("expected ErrInvalidRule, got %v", err)
		}
	})

	t.Run("label at max length passes", func(t *testing.T) {
		r := Rule{
			Action: ActionPass,
			Label:  strings.Repeat("a", 63),
		}
		if err := ValidateRule(r); err != nil {
			t.Fatalf("expected no error for 63-char label, got %v", err)
		}
	})

	t.Run("invalid interface chars", func(t *testing.T) {
		r := Rule{Action: ActionPass, Interface: "em.0"}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for dot in interface name")
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("expected ErrInvalidRule, got %v", err)
		}
	})

	t.Run("interface too long", func(t *testing.T) {
		r := Rule{Action: ActionPass, Interface: strings.Repeat("a", 16)}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for interface name >= 16 chars")
		}
	})

	t.Run("invalid port range from > to", func(t *testing.T) {
		r := Rule{
			Action:          ActionPass,
			DestinationPort: PortMatcher{Operator: PortOpIRG, From: 8080, To: 80},
		}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for port range with From > To")
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("expected ErrInvalidRule, got %v", err)
		}
	})

	t.Run("port operator with no port", func(t *testing.T) {
		r := Rule{
			Action:     ActionBlock,
			SourcePort: PortMatcher{Operator: PortOpEq, From: 0, To: 0},
		}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for port operator with no port specified")
		}
	})

	t.Run("invalid source table", func(t *testing.T) {
		r := Rule{
			Action: ActionPass,
			Source: Address{Table: "bad table"},
		}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for table name with spaces")
		}
	})

	t.Run("valid anchor name", func(t *testing.T) {
		r := Rule{
			Action: ActionPass,
			Anchor: "my/anchor",
		}
		if err := ValidateRule(r); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("anchor with whitespace", func(t *testing.T) {
		r := Rule{
			Action: ActionPass,
			Anchor: "bad anchor",
		}
		err := ValidateRule(r)
		if err == nil {
			t.Fatal("expected error for anchor with whitespace")
		}
	})
}

func TestValidateTableName(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		err := ValidateTableName("")
		if err == nil {
			t.Fatal("expected error for empty table name")
		}
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument, got %v", err)
		}
	})

	t.Run("too long", func(t *testing.T) {
		err := ValidateTableName(strings.Repeat("x", 32))
		if err == nil {
			t.Fatal("expected error for table name >= 32 chars")
		}
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument, got %v", err)
		}
	})

	t.Run("name with spaces", func(t *testing.T) {
		err := ValidateTableName("bad name")
		if err == nil {
			t.Fatal("expected error for table name with spaces")
		}
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument, got %v", err)
		}
	})

	t.Run("name with angle brackets", func(t *testing.T) {
		err := ValidateTableName("<badtable>")
		if err == nil {
			t.Fatal("expected error for table name with angle brackets")
		}
	})

	t.Run("valid name", func(t *testing.T) {
		if err := ValidateTableName("blocked_hosts"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("max valid length", func(t *testing.T) {
		name := strings.Repeat("a", 31)
		if err := ValidateTableName(name); err != nil {
			t.Fatalf("expected no error for 31-char name, got %v", err)
		}
	})
}

func TestValidateAddress(t *testing.T) {
	t.Run("valid table ref", func(t *testing.T) {
		addr := Address{Table: "blocked_hosts"}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("invalid table with spaces", func(t *testing.T) {
		addr := Address{Table: "bad table"}
		if err := validateAddress(addr); err == nil {
			t.Fatal("expected error for table name with spaces")
		}
	})

	t.Run("table name too long", func(t *testing.T) {
		addr := Address{Table: strings.Repeat("x", 32)}
		if err := validateAddress(addr); err == nil {
			t.Fatal("expected error for table name >= 32 chars")
		}
	})

	t.Run("valid network", func(t *testing.T) {
		_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
		addr := Address{Network: cidr}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("any address", func(t *testing.T) {
		addr := Address{Any: true}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error for any address, got %v", err)
		}
	})

	t.Run("valid IPv4", func(t *testing.T) {
		addr := Address{IP: net.ParseIP("10.0.0.1")}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("valid IPv6", func(t *testing.T) {
		addr := Address{IP: net.ParseIP("::1")}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("zero-value address passes", func(t *testing.T) {
		addr := Address{}
		if err := validateAddress(addr); err != nil {
			t.Fatalf("expected no error for zero-value address, got %v", err)
		}
	})
}

func TestValidatePort(t *testing.T) {
	t.Run("range from > to", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpIRG, From: 9000, To: 80}
		if err := validatePort(pm); err == nil {
			t.Fatal("expected error for port range From > To")
		}
	})

	t.Run("valid eq port", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpEq, From: 443}
		if err := validatePort(pm); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("no operator passes", func(t *testing.T) {
		pm := PortMatcher{}
		if err := validatePort(pm); err != nil {
			t.Fatalf("expected no error for PortOpNone, got %v", err)
		}
	})

	t.Run("valid inclusive range", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpIRG, From: 1024, To: 65535}
		if err := validatePort(pm); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("exclusive range from > to", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpXRG, From: 500, To: 100}
		if err := validatePort(pm); err == nil {
			t.Fatal("expected error for XRG range From > To")
		}
	})
}

func TestRuleSetAction(t *testing.T) {
	// DIOCGETRULES/DIOCGETRULE select the ruleset through a rule action
	// (pf_get_ruleset_number): pass->filter, scrub->scrub, nat, binat, rdr.
	want := map[RuleSet]uint8{
		RuleSetScrub:  pfActScrub,
		RuleSetFilter: pfActPass,
		RuleSetNAT:    pfActNAT,
		RuleSetBINAT:  pfActBINAT,
		RuleSetRDR:    pfActRDR,
	}
	for rs, act := range want {
		got, err := ruleSetAction(rs)
		if err != nil || got != act {
			t.Errorf("ruleSetAction(%d) = %d, %v; want %d", rs, got, err, act)
		}
	}
	for _, rs := range []RuleSet{-1, 5, 100} {
		if _, err := ruleSetAction(rs); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ruleSetAction(%d) err = %v; want ErrInvalidArgument", rs, err)
		}
	}
}

func TestCheckCString(t *testing.T) {
	if err := checkCString("interface", "tap0", 16); err != nil {
		t.Fatalf("short name: %v", err)
	}
	if err := checkCString("interface", strings.Repeat("a", 15), 16); err != nil {
		t.Fatalf("15 chars fit IFNAMSIZ 16 with the NUL: %v", err)
	}
	err := checkCString("interface", strings.Repeat("a", 16), 16)
	if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "interface") {
		t.Fatalf("16 chars: err = %v; want ErrInvalidArgument naming the field", err)
	}
	if err := checkCString("label", strings.Repeat("l", 64), 64); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("64-char label: err = %v; want ErrInvalidArgument", err)
	}
}

func TestValidateStateFilter(t *testing.T) {
	if err := validateStateFilter(StateFilter{Interface: "tap0", Label: "x"}); err != nil {
		t.Fatalf("valid filter: %v", err)
	}
	for _, f := range []StateFilter{
		{Interface: strings.Repeat("t", 16)},
		{Label: strings.Repeat("l", 64)},
	} {
		if err := validateStateFilter(f); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("validateStateFilter(%+v) = %v; want ErrInvalidArgument", f, err)
		}
	}
}

func TestCheckKillFlags(t *testing.T) {
	nat, match := StateFilter{NAT: true}, StateFilter{KillMatch: true}
	if err := checkKillFlags(nat, true, true); err != nil {
		t.Errorf("NAT supported: %v", err)
	}
	if err := checkKillFlags(StateFilter{}, false, false); err != nil {
		t.Errorf("no flags must pass on any kernel: %v", err)
	}
	// 13.x/14.x have no NAT matching and the fixed-struct ioctls no
	// kill-match: a request they would silently run without the flag
	// (killing the wrong states or none) must be refused instead.
	if err := checkKillFlags(nat, false, true); !errors.Is(err, ErrNotSupported) {
		t.Errorf("NAT unsupported = %v; want ErrNotSupported", err)
	}
	if err := checkKillFlags(match, true, false); !errors.Is(err, ErrNotSupported) {
		t.Errorf("KillMatch unsupported = %v; want ErrNotSupported", err)
	}
	if err := checkKillFlags(match, false, true); err != nil {
		t.Errorf("KillMatch supported: %v", err)
	}
}
