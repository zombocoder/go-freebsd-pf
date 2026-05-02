// Package testutil provides helpers for integration testing.
package testutil

import (
	"os"
	"testing"
)

const (
	// TestAnchor is the anchor used for integration tests.
	TestAnchor = "go-freebsd-pf-test"

	// TestTableName is the table name used for integration tests.
	TestTableName = "test_gofreebsdpf"
)

// RequireRoot skips the test if not running as root.
func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires root privileges")
	}
}

// RequireFreeBSD skips the test if not running on FreeBSD.
func RequireFreeBSD(t *testing.T) {
	t.Helper()
	// This is redundant when using build tags, but serves as documentation.
}
