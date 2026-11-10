//go:build !freebsd || !cgo

package pf

import "net"

// Options configures the PF client.
type Options struct {
	Device string
}

// Client provides access to the FreeBSD PF firewall.
type Client struct{}

func Open(_ Options) (*Client, error)      { return nil, ErrUnsupportedPlatform }
func OpenDefault() (*Client, error)        { return nil, ErrUnsupportedPlatform }
func (c *Client) Close() error             { return ErrUnsupportedPlatform }
func (c *Client) FD() uintptr              { return 0 }
func (c *Client) Enable() error            { return ErrUnsupportedPlatform }
func (c *Client) Disable() error           { return ErrUnsupportedPlatform }
func (c *Client) IsEnabled() (bool, error) { return false, ErrUnsupportedPlatform }
func (c *Client) Status() (*Status, error) { return nil, ErrUnsupportedPlatform }
func (c *Client) ClearStatus() error       { return ErrUnsupportedPlatform }

func (c *Client) ListRules(_ RuleQuery) ([]Rule, error) { return nil, ErrUnsupportedPlatform }
func (c *Client) AddRule(_ Rule) error                  { return ErrUnsupportedPlatform }
func (c *Client) ReplaceRules(_ string, _ []Rule) error { return ErrUnsupportedPlatform }
func (c *Client) ClearRules(_ string, _ RuleSet) error  { return ErrUnsupportedPlatform }

func (c *Client) Begin(_ string, _ ...RuleSet) (*Transaction, error) {
	return nil, ErrUnsupportedPlatform
}

func (c *Client) CreateTable(_ Table) error                            { return ErrUnsupportedPlatform }
func (c *Client) DeleteTable(_ Table) error                            { return ErrUnsupportedPlatform }
func (c *Client) ListTables(_ string) ([]Table, error)                 { return nil, ErrUnsupportedPlatform }
func (c *Client) AddTableAddresses(_ Table, _ []TableAddress) error    { return ErrUnsupportedPlatform }
func (c *Client) DeleteTableAddresses(_ Table, _ []TableAddress) error { return ErrUnsupportedPlatform }
func (c *Client) ReplaceTableAddresses(_ Table, _ []TableAddress) error {
	return ErrUnsupportedPlatform
}
func (c *Client) ListTableAddresses(_ Table) ([]TableAddress, error) {
	return nil, ErrUnsupportedPlatform
}
func (c *Client) TestTableAddress(_ Table, _ net.IP) (bool, error) {
	return false, ErrUnsupportedPlatform
}
func (c *Client) FlushTable(_ Table) error { return ErrUnsupportedPlatform }

func (c *Client) ListStates(_ StateFilter) ([]State, error) { return nil, ErrUnsupportedPlatform }
func (c *Client) ClearStates(_ StateFilter) (int, error)    { return 0, ErrUnsupportedPlatform }
func (c *Client) KillStates(_ StateFilter) (int, error)     { return 0, ErrUnsupportedPlatform }

// Transaction is a PF ruleset transaction.
type Transaction struct{}

func (tx *Transaction) AddRule(_ Rule) error { return ErrUnsupportedPlatform }
func (tx *Transaction) Commit() error        { return ErrUnsupportedPlatform }
func (tx *Transaction) Rollback() error      { return ErrUnsupportedPlatform }
