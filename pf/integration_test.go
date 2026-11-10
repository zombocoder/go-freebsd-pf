//go:build freebsd && cgo && integration

package pf

import (
	"net"
	"os"
	"testing"
)

const testAnchor = "go-freebsd-pf-test"

// openClient opens /dev/pf or skips the test if not possible.
func openClient(t *testing.T) *Client {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	c, err := OpenDefault()
	if err != nil {
		t.Fatalf("OpenDefault: %v", err)
	}
	return c
}

// cleanupAnchor removes all rules and tables from the test anchor.
func cleanupAnchor(t *testing.T, c *Client) {
	t.Helper()
	_ = c.ClearRules(testAnchor, RuleSetFilter)
}

func TestOpenClose(t *testing.T) {
	c := openClient(t)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestStatus(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	status, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	// We just verify we got a non-nil status; Running may be true or false.
	if status == nil {
		t.Fatal("Status returned nil without error")
	}
	t.Logf("PF running=%v since=%v debug=%v states=%d",
		status.Running, status.Since, status.Debug, status.States)
}

func TestEnableDisable(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	// enableSafePF skips unless PF is disabled with an empty main
	// ruleset, loads a pass-all ruleset, enables PF and restores the
	// original "disabled, no ruleset" state on cleanup.
	enableSafePF(t, c)

	status, err := c.Status()
	if err != nil {
		t.Fatalf("Status after Enable: %v", err)
	}
	if !status.Running {
		t.Error("expected PF to be running after Enable")
	}

	if err := c.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	status, err = c.Status()
	if err != nil {
		t.Fatalf("Status after Disable: %v", err)
	}
	if status.Running {
		t.Error("expected PF to be stopped after Disable")
	}
}

func TestListRulesEmpty(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	// Ensure the test anchor is clean.
	cleanupAnchor(t, c)

	rules, err := c.ListRules(RuleQuery{
		Anchor:  testAnchor,
		RuleSet: RuleSetFilter,
	})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules in empty test anchor, got %d", len(rules))
	}
}

func TestTransactionAddRule(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	// Clean up before and after.
	cleanupAnchor(t, c)
	defer cleanupAnchor(t, c)

	tx, err := c.Begin(testAnchor, RuleSetFilter)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	rule := Rule{
		Action:    ActionBlock,
		Direction: DirectionIn,
		Protocol:  ProtocolTCP,
		AF:        AddressFamilyIPv4,
		DestinationPort: PortMatcher{
			Operator: PortOpEq,
			From:     65534,
		},
	}

	if err := tx.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	rules, err := c.ListRules(RuleQuery{
		Anchor:  testAnchor,
		RuleSet: RuleSetFilter,
	})
	if err != nil {
		t.Fatalf("ListRules after commit: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", r.Action)
	}
	if r.Direction != DirectionIn {
		t.Errorf("expected DirectionIn, got %v", r.Direction)
	}
	if r.Protocol != ProtocolTCP {
		t.Errorf("expected ProtocolTCP, got %v", r.Protocol)
	}
	if r.DestinationPort.From != 65534 {
		t.Errorf("expected dest port 65534, got %d", r.DestinationPort.From)
	}

	// Clear the anchor.
	if err := c.ClearRules(testAnchor, RuleSetFilter); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}

	rules, err = c.ListRules(RuleQuery{
		Anchor:  testAnchor,
		RuleSet: RuleSetFilter,
	})
	if err != nil {
		t.Fatalf("ListRules after clear: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules after clear, got %d", len(rules))
	}
}

func TestCreateDeleteTable(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	table := Table{
		Name:   "test_gofreebsdpf",
		Anchor: testAnchor,
	}

	// Ensure clean state -- ignore error if table doesn't exist.
	_ = c.DeleteTable(table)

	if err := c.CreateTable(table); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}

	tables, err := c.ListTables(testAnchor)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}

	found := false
	for _, tbl := range tables {
		if tbl.Name == "test_gofreebsdpf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("table 'test_gofreebsdpf' not found in anchor %q; tables: %+v",
			testAnchor, tables)
	}

	if err := c.DeleteTable(table); err != nil {
		t.Fatalf("DeleteTable: %v", err)
	}

	tables, err = c.ListTables(testAnchor)
	if err != nil {
		t.Fatalf("ListTables after delete: %v", err)
	}
	for _, tbl := range tables {
		if tbl.Name == "test_gofreebsdpf" {
			t.Fatal("table 'test_gofreebsdpf' still exists after DeleteTable")
		}
	}
}

func TestTableAddresses(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	table := Table{
		Name:   "test_gofreebsdpf",
		Anchor: testAnchor,
	}

	// Clean up on exit.
	defer func() {
		_ = c.FlushTable(table)
		_ = c.DeleteTable(table)
	}()

	// Ensure clean state.
	_ = c.DeleteTable(table)

	if err := c.CreateTable(table); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}

	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	addrs := []TableAddress{
		{IP: net.ParseIP("192.0.2.1")},
		{Network: cidr},
	}

	if err := c.AddTableAddresses(table, addrs); err != nil {
		t.Fatalf("AddTableAddresses: %v", err)
	}

	listed, err := c.ListTableAddresses(table)
	if err != nil {
		t.Fatalf("ListTableAddresses: %v", err)
	}
	if len(listed) < 2 {
		t.Fatalf("expected at least 2 addresses, got %d", len(listed))
	}

	inTable, err := c.TestTableAddress(table, net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("TestTableAddress: %v", err)
	}
	if !inTable {
		t.Error("expected 192.0.2.1 to be in table")
	}

	if err := c.FlushTable(table); err != nil {
		t.Fatalf("FlushTable: %v", err)
	}

	listed, err = c.ListTableAddresses(table)
	if err != nil {
		t.Fatalf("ListTableAddresses after flush: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("expected 0 addresses after flush, got %d", len(listed))
	}

	if err := c.DeleteTable(table); err != nil {
		t.Fatalf("DeleteTable: %v", err)
	}
}

func TestListStates(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	_, err := c.ListStates(StateFilter{})
	if err != nil {
		t.Fatalf("ListStates: %v", err)
	}
}

func TestRollback(t *testing.T) {
	c := openClient(t)
	defer c.Close()

	// Ensure the test anchor is clean.
	cleanupAnchor(t, c)
	defer cleanupAnchor(t, c)

	tx, err := c.Begin(testAnchor, RuleSetFilter)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	rule := Rule{
		Action:    ActionBlock,
		Direction: DirectionIn,
		Protocol:  ProtocolTCP,
		AF:        AddressFamilyIPv4,
		DestinationPort: PortMatcher{
			Operator: PortOpEq,
			From:     65534,
		},
	}

	if err := tx.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	rules, err := c.ListRules(RuleQuery{
		Anchor:  testAnchor,
		RuleSet: RuleSetFilter,
	})
	if err != nil {
		t.Fatalf("ListRules after rollback: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules after rollback, got %d", len(rules))
	}
}
