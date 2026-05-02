//go:build freebsd && cgo

// Example: use a PF transaction to atomically add rules to an anchor,
// verify them, then clean up.
// Uses harmless ports (65533, 65532) — no impact on real traffic.
package main

import (
	"fmt"
	"log"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	const anchor = "txexample"

	// Begin a transaction
	fmt.Printf("Beginning transaction in anchor %q...\n", anchor)
	tx, err := client.Begin(anchor, pf.RuleSetFilter)
	if err != nil {
		log.Fatal("Failed to begin transaction: ", err)
	}

	// Rule 1: pass in proto tcp to port 65533 (harmless high port)
	rule1 := pf.Rule{
		Action:    pf.ActionPass,
		Direction: pf.DirectionIn,
		Protocol:  pf.ProtocolTCP,
		AF:        pf.AddressFamilyIPv4,
		Quick:     true,
		KeepState: true,
		Label:     "allow-test-65533",
		Source:    pf.Address{Any: true},
		Destination: pf.Address{Any: true},
		DestinationPort: pf.PortMatcher{
			Operator: pf.PortOpEq,
			From:     65533,
		},
	}

	fmt.Println("Adding rule: pass in quick proto tcp to port 65533")
	if err := tx.AddRule(rule1); err != nil {
		tx.Rollback()
		log.Fatal("Failed to add rule 1: ", err)
	}

	// Rule 2: block in proto tcp to port 65532 (harmless high port)
	rule2 := pf.Rule{
		Action:    pf.ActionBlock,
		Direction: pf.DirectionIn,
		Protocol:  pf.ProtocolTCP,
		AF:        pf.AddressFamilyIPv4,
		Quick:     true,
		KeepState: true,
		Label:     "block-test-65532",
		Source:    pf.Address{Any: true},
		Destination: pf.Address{Any: true},
		DestinationPort: pf.PortMatcher{
			Operator: pf.PortOpEq,
			From:     65532,
		},
	}

	fmt.Println("Adding rule: block in quick proto tcp to port 65532")
	if err := tx.AddRule(rule2); err != nil {
		tx.Rollback()
		log.Fatal("Failed to add rule 2: ", err)
	}

	// Commit the transaction
	fmt.Println("Committing transaction...")
	if err := tx.Commit(); err != nil {
		log.Fatal("Failed to commit transaction: ", err)
	}
	fmt.Println("Transaction committed.")

	// List the rules in the anchor to verify
	fmt.Printf("\nRules in anchor %q:\n", anchor)
	query := pf.RuleQuery{
		Anchor:  anchor,
		RuleSet: pf.RuleSetFilter,
	}

	rules, err := client.ListRules(query)
	if err != nil {
		log.Fatal("Failed to list rules: ", err)
	}

	for i, r := range rules {
		fmt.Printf("  %d: %s %s proto %s to port %d label %q\n",
			i, r.Action, r.Direction, r.Protocol,
			r.DestinationPort.From, r.Label)
	}

	// Clean up — clear the anchor
	fmt.Printf("\nCleaning up: clearing anchor %q...\n", anchor)
	if err := client.ClearRules(anchor, pf.RuleSetFilter); err != nil {
		log.Fatal("Failed to clear anchor: ", err)
	}
	fmt.Println("Anchor cleared. Done.")
}
