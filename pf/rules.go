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
#include <string.h>
*/
import "C"
import (
	"syscall"
	"unsafe"
)

// ListRules retrieves the rules matching the given query. An unknown
// query.RuleSet returns ErrInvalidArgument; an anchor that does not exist
// has no rules.
func (c *Client) ListRules(query RuleQuery) ([]Rule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	action, err := ruleSetAction(query.RuleSet)
	if err != nil {
		return nil, err
	}

	var pr C.struct_pfioc_rule
	C.memset(unsafe.Pointer(&pr), 0, C.sizeof_struct_pfioc_rule)

	if err := copyStringToC(&pr.anchor[0], "anchor", query.Anchor, C.MAXPATHLEN); err != nil {
		return nil, err
	}
	pr.rule.action = C.u_int8_t(action)

	if err := ioctlGetRules(c.fd, &pr); err != nil {
		// The kernel answers EINVAL for an anchor that does not exist
		// (pf_ioctl_getrules); committing an empty ruleset removes the
		// anchor, so report it as empty, as pfctl -a does.
		if query.Anchor != "" && isErrno(err, syscall.EINVAL) {
			return nil, nil
		}
		return nil, err
	}

	count := int(pr.nr)
	rules := make([]Rule, 0, count)
	ticket := pr.ticket

	for i := 0; i < count; i++ {
		var gr C.struct_pfioc_rule
		C.memset(unsafe.Pointer(&gr), 0, C.sizeof_struct_pfioc_rule)

		// Same anchor as above; it fits.
		_ = copyStringToC(&gr.anchor[0], "anchor", query.Anchor, C.MAXPATHLEN)
		gr.ticket = ticket
		gr.nr = C.u_int32_t(i)
		// Same ruleset selector as DIOCGETRULES, so the ticket matches.
		gr.rule.action = C.u_int8_t(action)

		if err := ioctlGetRule(c.fd, &gr); err != nil {
			return rules, err
		}

		rules = append(rules, ruleFromC(&gr))
	}

	return rules, nil
}

// MainRulesetHasAnchor reports whether the main filter ruleset contains an
// `anchor` rule calling path. path is compared with the kernel's spelling of
// the call (Rule.AnchorCall), ignoring one leading "/": "microvm-runner/*"
// matches `anchor "microvm-runner/*"` and `anchor "/microvm-runner/*"`.
// "microvm-runner" and "microvm-runner/*" are different calls. nat-anchor, rdr-anchor and binat-anchor rules are not looked at.
func (c *Client) MainRulesetHasAnchor(path string) (bool, error) {
	rules, err := c.ListRules(RuleQuery{RuleSet: RuleSetFilter})
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if sameAnchorCall(r.AnchorCall, path) {
			return true, nil
		}
	}
	return false, nil
}

// AddRule adds a single rule to PF outside a transaction.
//
// Deprecated: the kernel only accepts DIOCADDRULE with the ticket of an
// open transaction, so this call fails (EINVAL on FreeBSD 15.1). Use
// Client.Begin with Transaction.AddRule and Transaction.Commit, or
// Client.ReplaceRules, instead.
func (c *Client) AddRule(rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	pr, err := ruleToC(rule, rule.Anchor)
	if err != nil {
		return err
	}
	pr.action = C.PF_CHANGE_ADD_TAIL
	pr.pool_ticket = 0

	return ioctlAddRule(c.fd, &pr)
}

// ReplaceRules atomically replaces all rules in the given anchor
// with the provided rules. Uses a PF transaction internally.
func (c *Client) ReplaceRules(anchor string, rules []Rule) error {
	for _, r := range rules {
		if err := ValidateRule(r); err != nil {
			return err
		}
	}

	tx, err := c.Begin(anchor, RuleSetFilter)
	if err != nil {
		return err
	}

	for _, r := range rules {
		if err := tx.AddRule(r); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// ClearRules removes all rules from the given anchor and ruleset.
func (c *Client) ClearRules(anchor string, ruleset RuleSet) error {
	tx, err := c.Begin(anchor, ruleset)
	if err != nil {
		return err
	}
	return tx.Commit()
}
