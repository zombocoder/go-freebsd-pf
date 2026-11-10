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

static void set_states_v2_buf(struct pfioc_states_v2 *ps, void *buf) {
	ps->ps_buf = buf;
}
*/
import "C"
import (
	"unsafe"
)

// ListStates returns PF state table entries matching the filter.
// An empty filter returns all states.
func (c *Client) ListStates(filter StateFilter) ([]State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	var ps C.struct_pfioc_states_v2
	C.memset(unsafe.Pointer(&ps), 0, C.sizeof_struct_pfioc_states_v2)
	ps.ps_req_version = C.PF_STATE_VERSION

	// First call: get required buffer size
	ps.ps_len = 0
	C.set_states_v2_buf(&ps, nil)
	if err := ioctlGetStatesV2(c.fd, &ps); err != nil {
		return nil, err
	}

	if ps.ps_len == 0 {
		return nil, nil
	}

	buf := C.malloc(C.size_t(ps.ps_len))
	if buf == nil {
		return nil, &OpError{Op: "ListStates", Err: ErrInvalidArgument}
	}
	defer C.free(buf)

	C.set_states_v2_buf(&ps, buf)
	if err := ioctlGetStatesV2(c.fd, &ps); err != nil {
		return nil, err
	}

	count := int(ps.ps_len) / int(C.sizeof_struct_pf_state_export)
	states := make([]State, 0, count)

	for i := 0; i < count; i++ {
		cs := (*C.struct_pf_state_export)(unsafe.Add(buf, i*int(C.sizeof_struct_pf_state_export)))
		s := stateFromC(cs)
		if matchesFilter(s, filter) {
			states = append(states, s)
		}
	}

	return states, nil
}

// ClearStates clears states matching the filter.
// Returns the number of states cleared.
func (c *Client) ClearStates(filter StateFilter) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return 0, err
	}

	psk := cStateKill(filter)
	if err := ioctlClearStates(c.fd, &psk); err != nil {
		return 0, err
	}

	return int(psk.psk_killed), nil
}

// KillStates kills states matching the filter.
// Returns the number of states killed.
func (c *Client) KillStates(filter StateFilter) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return 0, err
	}

	psk := cStateKill(filter)
	if err := ioctlKillStates(c.fd, &psk); err != nil {
		return 0, err
	}

	return int(psk.psk_killed), nil
}
