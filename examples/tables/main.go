//go:build freebsd && cgo

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
	fmt.Println("WARNING: This program requires root privileges.")

	client, err := pf.OpenDefault()
	if err != nil {
		log.Fatal("Failed to open PF: ", err)
	}
	defer client.Close()

	table := pf.Table{
		Name:   "example_blocklist",
		Anchor: "",
		Flags:  pf.TableFlagPersist,
	}

	// Create the table
	fmt.Println("Creating table:", table.Name)
	if err := client.CreateTable(table); err != nil {
		log.Fatal("Failed to create table: ", err)
	}
	fmt.Println("Table created.")

	// Add addresses
	_, cidr, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		log.Fatal("Failed to parse CIDR: ", err)
	}

	addrs := []pf.TableAddress{
		{IP: net.ParseIP("192.0.2.10")},
		{Network: cidr},
	}

	fmt.Println("Adding addresses to table...")
	if err := client.AddTableAddresses(table, addrs); err != nil {
		log.Fatal("Failed to add addresses: ", err)
	}
	fmt.Println("Addresses added.")

	// List addresses
	fmt.Println("\nListing table addresses:")
	listed, err := client.ListTableAddresses(table)
	if err != nil {
		log.Fatal("Failed to list addresses: ", err)
	}
	for _, a := range listed {
		if a.Network != nil {
			fmt.Printf("  %s\n", a.Network)
		} else if a.IP != nil {
			fmt.Printf("  %s\n", a.IP)
		}
	}

	// Test an address
	testIP := net.ParseIP("192.0.2.10")
	found, err := client.TestTableAddress(table, testIP)
	if err != nil {
		log.Fatal("Failed to test address: ", err)
	}
	fmt.Printf("\nTest %s in table: %v\n", testIP, found)

	// Flush the table
	fmt.Println("\nFlushing table...")
	if err := client.FlushTable(table); err != nil {
		log.Fatal("Failed to flush table: ", err)
	}
	fmt.Println("Table flushed.")

	// Delete the table
	fmt.Println("Deleting table...")
	if err := client.DeleteTable(table); err != nil {
		log.Fatal("Failed to delete table: ", err)
	}
	fmt.Println("Table deleted.")
}
