//go:build freebsd && cgo

package pf

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
*/
import "C"
import "time"

// Enable enables the PF firewall (DIOCSTART).
func (c *Client) Enable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}
	return ioctlStart(c.fd)
}

// Disable disables the PF firewall (DIOCSTOP).
func (c *Client) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}
	return ioctlStop(c.fd)
}

// IsEnabled returns true if PF is currently running.
func (c *Client) IsEnabled() (bool, error) {
	s, err := c.Status()
	if err != nil {
		return false, err
	}
	return s.Running, nil
}

// Status retrieves PF status information (DIOCGETSTATUS).
func (c *Client) Status() (*Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	cs, err := ioctlGetStatus(c.fd)
	if err != nil {
		return nil, err
	}

	return convertStatus(&cs), nil
}

// ClearStatus clears PF status counters (DIOCCLRSTATUS).
func (c *Client) ClearStatus() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}
	return ioctlClearStatus(c.fd)
}

func convertStatus(cs *C.struct_pf_status) *Status {
	s := &Status{
		Running:  cs.running != 0,
		Since:    time.Unix(int64(cs.since), 0),
		Debug:    DebugLevel(cs.debug),
		HostID:   uint32(cs.hostid),
		States:   uint32(cs.states),
		SrcNodes: uint32(cs.src_nodes),
	}

	// Copy interface name
	s.Interface = C.GoString(&cs.ifname[0])

	// Copy counters
	s.Counters.Counters = make([]uint64, C.PFRES_MAX)
	for i := 0; i < int(C.PFRES_MAX); i++ {
		s.Counters.Counters[i] = uint64(cs.counters[i])
	}

	s.Counters.LCounters = make([]uint64, C.LCNT_MAX)
	for i := 0; i < int(C.LCNT_MAX); i++ {
		s.Counters.LCounters[i] = uint64(cs.lcounters[i])
	}

	s.Counters.FCounters = make([]uint64, C.FCNT_MAX)
	for i := 0; i < int(C.FCNT_MAX); i++ {
		s.Counters.FCounters[i] = uint64(cs.fcounters[i])
	}

	s.Counters.SCounters = make([]uint64, C.SCNT_MAX)
	for i := 0; i < int(C.SCNT_MAX); i++ {
		s.Counters.SCounters[i] = uint64(cs.scounters[i])
	}

	// Copy checksum
	for i := 0; i < 16; i++ {
		s.Checksum[i] = byte(cs.pf_chksum[i])
	}

	return s
}
