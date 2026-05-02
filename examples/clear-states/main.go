//go:build freebsd && cgo

// Example: list PF states. Optionally clear states with -clear flag.
// Without -clear, this is read-only and safe to run.
//
// WARNING: Clearing states will drop ALL active connections including SSH.
// Only use -clear if you have console access or understand the consequences.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	doClear := flag.Bool("clear", false, "actually clear states (DANGER: drops all connections including SSH)")
	flag.Parse()

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	// List current states (read-only, always safe)
	states, err := client.ListStates(pf.StateFilter{})
	if err != nil {
		log.Fatal("Failed to list states: ", err)
	}
	fmt.Printf("Current state count: %d\n", len(states))

	for i, s := range states {
		fmt.Printf("  [%d] %s %s:%d -> %s:%d (%s)\n",
			i, s.Protocol, s.Source, s.SourcePort,
			s.Destination, s.DestPort, s.Interface)
		if i >= 19 {
			fmt.Printf("  ... and %d more\n", len(states)-20)
			break
		}
	}

	if !*doClear {
		fmt.Println("\nTo clear states, run with -clear flag.")
		fmt.Println("WARNING: -clear will drop ALL connections including SSH!")
		return
	}

	fmt.Println("\nClearing all states...")
	cleared, err := client.ClearStates(pf.StateFilter{})
	if err != nil {
		log.Fatal("Failed to clear states: ", err)
	}
	fmt.Printf("Cleared %d state(s).\n", cleared)
}
