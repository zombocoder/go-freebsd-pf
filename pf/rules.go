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

// ListRules retrieves the rules matching the given query.
func (c *Client) ListRules(query RuleQuery) ([]Rule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	var pr C.struct_pfioc_rule
	C.memset(unsafe.Pointer(&pr), 0, C.sizeof_struct_pfioc_rule)

	if query.Anchor != "" {
		copyStringToC(&pr.anchor[0], query.Anchor, C.MAXPATHLEN)
	}
	pr.rule.action = C.u_int8_t(query.RuleSet)

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

		if query.Anchor != "" {
			copyStringToC(&gr.anchor[0], query.Anchor, C.MAXPATHLEN)
		}
		gr.ticket = ticket
		gr.nr = C.u_int32_t(i)
		// Same ruleset selector as DIOCGETRULES, so the ticket matches.
		gr.rule.action = C.u_int8_t(query.RuleSet)

		if err := ioctlGetRule(c.fd, &gr); err != nil {
			return rules, err
		}

		rules = append(rules, ruleFromC(&gr))
	}

	return rules, nil
}

// AddRule adds a single rule to PF. For transactional rule loading,
// use Begin/Transaction instead.
func (c *Client) AddRule(rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	pr := ruleToC(rule, rule.Anchor)
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
