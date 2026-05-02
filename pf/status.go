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

	// Counters (PFRES_* — the "Counters" section of pfctl -s info)
	s.Counters = StatusCounters{
		Match:         uint64(cs.counters[C.PFRES_MATCH]),
		BadOffset:     uint64(cs.counters[C.PFRES_BADOFF]),
		Fragment:      uint64(cs.counters[C.PFRES_FRAG]),
		Short:         uint64(cs.counters[C.PFRES_SHORT]),
		Normalize:     uint64(cs.counters[C.PFRES_NORM]),
		Memory:        uint64(cs.counters[C.PFRES_MEMORY]),
		BadTimestamp:  uint64(cs.counters[C.PFRES_TS]),
		Congestion:    uint64(cs.counters[C.PFRES_CONGEST]),
		IPOption:      uint64(cs.counters[C.PFRES_IPOPTIONS]),
		ProtoChecksum: uint64(cs.counters[C.PFRES_PROTCKSUM]),
		StateMismatch: uint64(cs.counters[C.PFRES_BADSTATE]),
		StateInsert:   uint64(cs.counters[C.PFRES_STATEINS]),
		StateLimit:    uint64(cs.counters[C.PFRES_MAXSTATES]),
		SrcLimit:      uint64(cs.counters[C.PFRES_SRCLIMIT]),
		SynProxy:      uint64(cs.counters[C.PFRES_SYNPROXY]),
		MapFailed:     uint64(cs.counters[C.PFRES_MAPFAILED]),
	}

	// State table counters (FCNT_* — the "State Table" section)
	s.StateTable = StateTableCounters{
		Searches: uint64(cs.fcounters[C.FCNT_STATE_SEARCH]),
		Inserts:  uint64(cs.fcounters[C.FCNT_STATE_INSERT]),
		Removals: uint64(cs.fcounters[C.FCNT_STATE_REMOVALS]),
	}

	// Copy checksum
	for i := 0; i < 16; i++ {
		s.Checksum[i] = byte(cs.pf_chksum[i])
	}

	return s
}
