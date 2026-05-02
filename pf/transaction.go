//go:build freebsd && cgo

package pf

/*
#cgo freebsd CFLAGS: -D__BSD_VISIBLE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"sync"
	"unsafe"
)

// Transaction represents a PF ruleset transaction.
// Rules added via AddRule are committed atomically on Commit.
type Transaction struct {
	mu       sync.Mutex
	client   *Client
	anchor   string
	rulesets []RuleSet
	trans    C.struct_pfioc_trans
	elems    []C.struct_pfioc_trans_e
	closed   bool
}

// Begin starts a new PF transaction for the specified anchor and rulesets.
// The transaction must be committed or rolled back.
func (c *Client) Begin(anchor string, rulesets ...RuleSet) (*Transaction, error) {
	if len(rulesets) == 0 {
		rulesets = []RuleSet{RuleSetFilter}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	tx := &Transaction{
		client:   c,
		anchor:   anchor,
		rulesets: rulesets,
	}

	// Allocate transaction elements
	tx.elems = make([]C.struct_pfioc_trans_e, len(rulesets))
	for i, rs := range rulesets {
		C.memset(unsafe.Pointer(&tx.elems[i]), 0, C.sizeof_struct_pfioc_trans_e)
		tx.elems[i].rs_num = C.int(rs)
		if anchor != "" {
			copyStringToC(&tx.elems[i].anchor[0], anchor, C.MAXPATHLEN)
		}
	}

	tx.trans.size = C.int(len(rulesets))
	tx.trans.esize = C.int(C.sizeof_struct_pfioc_trans_e)
	tx.trans.array = &tx.elems[0]

	if err := ioctlXBegin(c.fd, &tx.trans); err != nil {
		return nil, err
	}

	return tx, nil
}

// AddRule adds a rule to this transaction.
func (tx *Transaction) AddRule(rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.closed {
		return ErrTransactionClosed
	}

	tx.client.mu.Lock()
	defer tx.client.mu.Unlock()

	pr := ruleToC(rule, tx.anchor)
	pr.ticket = tx.elems[0].ticket
	pr.pool_ticket = 0

	return ioctlAddRule(tx.client.fd, &pr)
}

// Commit commits the transaction, making all added rules active atomically.
func (tx *Transaction) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.closed {
		return ErrTransactionClosed
	}
	tx.closed = true

	tx.client.mu.Lock()
	defer tx.client.mu.Unlock()

	return ioctlXCommit(tx.client.fd, &tx.trans)
}

// Rollback aborts the transaction, discarding all added rules.
func (tx *Transaction) Rollback() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.closed {
		return ErrTransactionClosed
	}
	tx.closed = true

	tx.client.mu.Lock()
	defer tx.client.mu.Unlock()

	return ioctlXRollback(tx.client.fd, &tx.trans)
}
