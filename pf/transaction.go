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

// Allocate and initialize a pfioc_trans with its element array in a single
// C allocation so there are no Go pointers involved.
static struct pfioc_trans* alloc_trans(int n) {
	struct pfioc_trans *pt = calloc(1, sizeof(struct pfioc_trans));
	if (!pt) return NULL;
	struct pfioc_trans_e *elems = calloc(n, sizeof(struct pfioc_trans_e));
	if (!elems) { free(pt); return NULL; }
	pt->size = n;
	pt->esize = sizeof(struct pfioc_trans_e);
	pt->array = elems;
	return pt;
}

static void free_trans(struct pfioc_trans *pt) {
	if (pt) {
		free(pt->array);
		free(pt);
	}
}

static struct pfioc_trans_e* trans_elem(struct pfioc_trans *pt, int i) {
	return &pt->array[i];
}

static int pf_do_xbegin(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXBEGIN, pt);
}

static int pf_do_xcommit(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXCOMMIT, pt);
}

static int pf_do_xrollback(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXROLLBACK, pt);
}
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
	ctrans   *C.struct_pfioc_trans // fully C-allocated
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

	n := len(rulesets)
	tx := &Transaction{
		client:   c,
		anchor:   anchor,
		rulesets: rulesets,
	}

	tx.ctrans = C.alloc_trans(C.int(n))
	if tx.ctrans == nil {
		return nil, &OpError{Op: "Begin", Err: ErrInvalidArgument}
	}

	for i, rs := range rulesets {
		elem := C.trans_elem(tx.ctrans, C.int(i))
		elem.rs_num = C.int(rs)
		if err := copyStringToC(&elem.anchor[0], "anchor", anchor, C.MAXPATHLEN); err != nil {
			C.free_trans(tx.ctrans)
			tx.ctrans = nil
			return nil, err
		}
	}

	rv, err := C.pf_do_xbegin(C.int(c.fd), tx.ctrans)
	if ioctlErr("DIOCXBEGIN", rv, err) != nil {
		C.free_trans(tx.ctrans)
		tx.ctrans = nil
		return nil, ioctlErr("DIOCXBEGIN", rv, err)
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

	pr, err := ruleToC(rule, tx.anchor)
	if err != nil {
		return err
	}
	elem := C.trans_elem(tx.ctrans, 0)
	pr.ticket = elem.ticket
	poolTicket, err := ioctlBeginAddrs(tx.client.fd)
	if err != nil {
		return err
	}
	pr.pool_ticket = poolTicket

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

	rv, err := C.pf_do_xcommit(C.int(tx.client.fd), tx.ctrans)
	e := ioctlErr("DIOCXCOMMIT", rv, err)
	C.free_trans(tx.ctrans)
	tx.ctrans = nil
	return e
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

	rv, err := C.pf_do_xrollback(C.int(tx.client.fd), tx.ctrans)
	e := ioctlErr("DIOCXROLLBACK", rv, err)
	C.free_trans(tx.ctrans)
	tx.ctrans = nil
	return e
}

// ticket returns the ticket for the first ruleset. Used by ClearRules.
func (tx *Transaction) ticket() C.u_int32_t {
	elem := C.trans_elem(tx.ctrans, 0)
	return elem.ticket
}

// Ensure ioctlErr is accessible (defined in cgo_freebsd.go)
var _ = unsafe.Pointer(nil) // keep unsafe import
