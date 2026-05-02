//go:build freebsd && cgo

// Example: check PF status, optionally toggle enable/disable.
// By default this is read-only. Use -toggle to actually enable/disable PF.
// The original PF state is always restored at the end.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	doToggle := flag.Bool("toggle", false, "actually toggle PF enable/disable (will restore original state)")
	flag.Parse()

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	// Read current status
	wasEnabled, err := client.IsEnabled()
	if err != nil {
		log.Fatal("Failed to check PF status: ", err)
	}
	fmt.Printf("PF currently running: %v\n", wasEnabled)

	if !*doToggle {
		fmt.Println("\nTo toggle PF enable/disable, run with -toggle flag.")
		fmt.Println("The original state will be restored automatically.")
		return
	}

	// Ensure we restore original state on exit
	defer func() {
		fmt.Printf("\nRestoring original PF state (enabled=%v)...\n", wasEnabled)
		if wasEnabled {
			if err := client.Enable(); err != nil {
				// May get "already enabled" — that's fine
				fmt.Println("  Enable:", err)
			} else {
				fmt.Println("  PF re-enabled.")
			}
		} else {
			if err := client.Disable(); err != nil {
				fmt.Println("  Disable:", err)
			} else {
				fmt.Println("  PF re-disabled.")
			}
		}
	}()

	// Toggle: if enabled, disable then re-enable; if disabled, enable then disable
	if wasEnabled {
		fmt.Println("\nDisabling PF...")
		if err := client.Disable(); err != nil {
			log.Fatal("Failed to disable PF: ", err)
		}
		fmt.Println("PF disabled.")

		enabled, _ := client.IsEnabled()
		fmt.Printf("PF running: %v\n", enabled)

		fmt.Println("\nRe-enabling PF...")
		if err := client.Enable(); err != nil {
			log.Fatal("Failed to enable PF: ", err)
		}
		fmt.Println("PF enabled.")
	} else {
		fmt.Println("\nEnabling PF...")
		if err := client.Enable(); err != nil {
			log.Fatal("Failed to enable PF: ", err)
		}
		fmt.Println("PF enabled.")

		enabled, _ := client.IsEnabled()
		fmt.Printf("PF running: %v\n", enabled)

		fmt.Println("\nDisabling PF...")
		if err := client.Disable(); err != nil {
			log.Fatal("Failed to disable PF: ", err)
		}
		fmt.Println("PF disabled.")
	}
}
