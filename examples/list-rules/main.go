//go:build freebsd && cgo

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	anchor := flag.String("anchor", "", "anchor name (empty for root)")
	flag.Parse()

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	query := pf.RuleQuery{
		Anchor:  *anchor,
		RuleSet: pf.RuleSetFilter,
	}

	rules, err := client.ListRules(query)
	if err != nil {
		log.Fatal("Failed to list rules: ", err)
	}

	if len(rules) == 0 {
		fmt.Println("No rules found.")
		return
	}

	fmt.Printf("Found %d rule(s):\n\n", len(rules))
	for i, r := range rules {
		fmt.Printf("Rule #%d:\n", i)
		fmt.Printf("  Action:    %s\n", r.Action)
		fmt.Printf("  Direction: %s\n", r.Direction)
		fmt.Printf("  Interface: %s\n", r.Interface)
		fmt.Printf("  Protocol:  %s\n", r.Protocol)
		fmt.Printf("  Source:     %s\n", formatAddress(r.Source))
		fmt.Printf("  Dest:       %s\n", formatAddress(r.Destination))
		fmt.Printf("  SrcPort:   %s\n", formatPort(r.SourcePort))
		fmt.Printf("  DstPort:   %s\n", formatPort(r.DestinationPort))
		fmt.Printf("  Quick:     %v\n", r.Quick)
		fmt.Printf("  Log:       %v\n", r.Log)
		fmt.Printf("  Label:     %s\n", r.Label)
		fmt.Println()
	}
}

func formatAddress(addr pf.Address) string {
	if addr.Any {
		return "any"
	}
	if addr.Table != "" {
		return "<" + addr.Table + ">"
	}
	if addr.Network != nil {
		return addr.Network.String()
	}
	if addr.IP != nil {
		return addr.IP.String()
	}
	return "any"
}

func formatPort(pm pf.PortMatcher) string {
	if pm.IsAny() {
		return "any"
	}
	if pm.Operator == pf.PortOpEq {
		return fmt.Sprintf("= %d", pm.From)
	}
	return fmt.Sprintf("op=%d from=%d to=%d", pm.Operator, pm.From, pm.To)
}
