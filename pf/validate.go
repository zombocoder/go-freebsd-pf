package pf

import (
	"fmt"
	"net"
	"strings"
)

// ValidateRule checks that a rule has valid fields.
func ValidateRule(r Rule) error {
	if r.Action != ActionPass && r.Action != ActionBlock && r.Action != ActionMatch {
		return fmt.Errorf("%w: invalid action %d", ErrInvalidRule, r.Action)
	}

	if r.Interface != "" {
		if err := validateInterfaceName(r.Interface); err != nil {
			return err
		}
	}

	if err := validateAddress(r.Source); err != nil {
		return fmt.Errorf("%w: source: %v", ErrInvalidRule, err)
	}
	if err := validateAddress(r.Destination); err != nil {
		return fmt.Errorf("%w: destination: %v", ErrInvalidRule, err)
	}

	if err := validatePort(r.SourcePort); err != nil {
		return fmt.Errorf("%w: source port: %v", ErrInvalidRule, err)
	}
	if err := validatePort(r.DestinationPort); err != nil {
		return fmt.Errorf("%w: destination port: %v", ErrInvalidRule, err)
	}

	if r.Label != "" && len(r.Label) >= 64 {
		return fmt.Errorf("%w: label too long (max 63 chars)", ErrInvalidRule)
	}

	if r.Anchor != "" {
		if err := validateAnchorName(r.Anchor); err != nil {
			return err
		}
	}

	return nil
}

func validateInterfaceName(name string) error {
	if len(name) == 0 || len(name) >= 16 {
		return fmt.Errorf("%w: interface name must be 1-15 chars", ErrInvalidRule)
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return fmt.Errorf("%w: invalid character in interface name: %c", ErrInvalidRule, c)
		}
	}
	return nil
}

func validateAddress(addr Address) error {
	if addr.Any {
		return nil
	}
	if addr.Table != "" {
		if strings.ContainsAny(addr.Table, " \t\n<>") {
			return fmt.Errorf("invalid table name: %q", addr.Table)
		}
		if len(addr.Table) >= 32 {
			return fmt.Errorf("table name too long (max 31 chars)")
		}
		return nil
	}
	if addr.Network != nil {
		ones, bits := addr.Network.Mask.Size()
		if ones == 0 && bits == 0 {
			return fmt.Errorf("invalid CIDR mask")
		}
		return nil
	}
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			return nil
		}
		if len(addr.IP) == net.IPv6len {
			return nil
		}
		return fmt.Errorf("invalid IP address")
	}
	return nil
}

func validatePort(pm PortMatcher) error {
	if pm.Operator == PortOpNone {
		return nil
	}
	if pm.From == 0 && pm.To == 0 {
		return fmt.Errorf("port operator set but no port specified")
	}
	if pm.Operator == PortOpIRG || pm.Operator == PortOpXRG || pm.Operator == PortOpRRG {
		if pm.From > pm.To {
			return fmt.Errorf("port range start %d > end %d", pm.From, pm.To)
		}
	}
	return nil
}

func validateAnchorName(name string) error {
	if len(name) >= 1024 {
		return fmt.Errorf("%w: anchor name too long", ErrInvalidRule)
	}
	if strings.ContainsAny(name, " \t\n") {
		return fmt.Errorf("%w: anchor name contains whitespace", ErrInvalidRule)
	}
	return nil
}

// ValidateTableName checks a table name.
func ValidateTableName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty table name", ErrInvalidArgument)
	}
	if len(name) >= 32 {
		return fmt.Errorf("%w: table name too long (max 31 chars)", ErrInvalidArgument)
	}
	if strings.ContainsAny(name, " \t\n<>") {
		return fmt.Errorf("%w: invalid character in table name", ErrInvalidArgument)
	}
	return nil
}

// Rule actions from <netpfil/pf/pf.h> used to select a ruleset in
// DIOCGETRULES/DIOCGETRULE (the kernel's pf_get_ruleset_number). They have
// not changed since PF was imported; convert.go checks them against the
// header at compile time.
const (
	pfActPass  = 0 // PF_PASS  -> PF_RULESET_FILTER
	pfActScrub = 2 // PF_SCRUB -> PF_RULESET_SCRUB
	pfActNAT   = 4 // PF_NAT   -> PF_RULESET_NAT
	pfActBINAT = 6 // PF_BINAT -> PF_RULESET_BINAT
	pfActRDR   = 8 // PF_RDR   -> PF_RULESET_RDR
)

// ruleSetAction returns the rule action that selects rs in DIOCGETRULES.
// An unknown RuleSet is rejected here, so an EINVAL from the kernel can
// only mean a missing anchor.
func ruleSetAction(rs RuleSet) (uint8, error) {
	switch rs {
	case RuleSetScrub:
		return pfActScrub, nil
	case RuleSetFilter:
		return pfActPass, nil
	case RuleSetNAT:
		return pfActNAT, nil
	case RuleSetBINAT:
		return pfActBINAT, nil
	case RuleSetRDR:
		return pfActRDR, nil
	}
	return 0, fmt.Errorf("%w: unknown rule set %d", ErrInvalidArgument, rs)
}
