//go:build freebsd && cgo

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	s, err := client.Status()
	if err != nil {
		log.Fatal("Failed to get PF status: ", err)
	}

	// General status
	state := "Disabled"
	if s.Running {
		state = "Enabled"
	}
	uptime := time.Since(s.Since).Truncate(time.Second)
	fmt.Printf("Status: %s for %s\t\tDebug: %s\n", state, uptime, s.Debug)
	fmt.Println()

	// State table
	fmt.Println("State Table                          Total")
	fmt.Printf("  current entries                   %6d\n", s.States)
	fmt.Printf("  searches                      %10d\n", s.StateTable.Searches)
	fmt.Printf("  inserts                       %10d\n", s.StateTable.Inserts)
	fmt.Printf("  removals                      %10d\n", s.StateTable.Removals)
	fmt.Println()

	// Counters
	fmt.Println("Counters")
	printCounter("match", s.Counters.Match)
	printCounter("bad-offset", s.Counters.BadOffset)
	printCounter("fragment", s.Counters.Fragment)
	printCounter("short", s.Counters.Short)
	printCounter("normalize", s.Counters.Normalize)
	printCounter("memory", s.Counters.Memory)
	printCounter("bad-timestamp", s.Counters.BadTimestamp)
	printCounter("congestion", s.Counters.Congestion)
	printCounter("ip-option", s.Counters.IPOption)
	printCounter("proto-cksum", s.Counters.ProtoChecksum)
	printCounter("state-mismatch", s.Counters.StateMismatch)
	printCounter("state-insert", s.Counters.StateInsert)
	printCounter("state-limit", s.Counters.StateLimit)
	printCounter("src-limit", s.Counters.SrcLimit)
	printCounter("synproxy", s.Counters.SynProxy)
	printCounter("map-failed", s.Counters.MapFailed)
	fmt.Println()

	fmt.Printf("Source Tracking Nodes:  %d\n", s.SrcNodes)
	fmt.Printf("Host ID:               0x%08x\n", s.HostID)
}

func printCounter(name string, value uint64) {
	fmt.Printf("  %-24s %10d\n", name, value)
}
