//go:build freebsd && cgo

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

	status, err := client.Status()
	if err != nil {
		log.Fatal("Failed to get PF status: ", err)
	}

	fmt.Printf("Running:   %v\n", status.Running)
	fmt.Printf("Since:     %v\n", status.Since)
	fmt.Printf("States:    %d\n", status.States)
	fmt.Printf("SrcNodes:  %d\n", status.SrcNodes)
	fmt.Printf("Interface: %s\n", status.Interface)
	fmt.Printf("Debug:     %s\n", status.Debug)
	fmt.Printf("HostID:    0x%08x\n", status.HostID)
}
