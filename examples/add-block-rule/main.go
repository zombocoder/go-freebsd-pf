//go:build freebsd && cgo

// Example: add a temporary block rule to a test anchor, verify it, then remove it.
// Uses a high unused port (65534) to avoid disrupting any real traffic.
package main

import (
	"fmt"
	"log"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")
	fmt.Println("This example adds a rule to anchor \"example\", verifies it, then removes it.")

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	const anchor = "example"

	// Block an unused high port — never SSH (22) or anything in use.
	rule := pf.Rule{
		Action:    pf.ActionBlock,
		Direction: pf.DirectionIn,
		Protocol:  pf.ProtocolTCP,
		AF:        pf.AddressFamilyIPv4,
		Quick:     true,
		KeepState: true,
		Label:     "block-test-example",
		Source:    pf.Address{Any: true},
		Destination: pf.Address{Any: true},
		DestinationPort: pf.PortMatcher{
			Operator: pf.PortOpEq,
			From:     65534, // harmless unused port
		},
	}

	// Add rule via transaction
	fmt.Printf("Adding block rule (port 65534) to anchor %q...\n", anchor)
	tx, err := client.Begin(anchor, pf.RuleSetFilter)
	if err != nil {
		log.Fatal("Failed to begin transaction: ", err)
	}

	if err := tx.AddRule(rule); err != nil {
		tx.Rollback()
		log.Fatal("Failed to add rule: ", err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal("Failed to commit transaction: ", err)
	}
	fmt.Println("Rule committed successfully.")

	// Verify by listing
	rules, err := client.ListRules(pf.RuleQuery{Anchor: anchor, RuleSet: pf.RuleSetFilter})
	if err != nil {
		log.Fatal("Failed to list rules: ", err)
	}
	fmt.Printf("Found %d rule(s) in anchor %q:\n", len(rules), anchor)
	for i, r := range rules {
		fmt.Printf("  %d: %s %s proto %s to port %d label %q\n",
			i, r.Action, r.Direction, r.Protocol,
			r.DestinationPort.From, r.Label)
	}

	// Clean up — remove the rule by clearing the anchor
	fmt.Printf("\nCleaning up: clearing anchor %q...\n", anchor)
	if err := client.ClearRules(anchor, pf.RuleSetFilter); err != nil {
		log.Fatal("Failed to clear anchor: ", err)
	}
	fmt.Println("Anchor cleared. Done.")
}
