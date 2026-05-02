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
	"net"
	"unsafe"
)

// CreateTable creates a new PF table.
func (c *Client) CreateTable(table Table) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)

	ct := cPfrTable(table)
	ct.pfrt_flags |= C.u_int32_t(TableFlagPersist)
	pt.pfrio_table = ct
	pt.pfrio_buffer = unsafe.Pointer(&ct)
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_table)
	pt.pfrio_size = 1

	return ioctlTableAdd(c.fd, &pt)
}

// DeleteTable deletes a PF table.
func (c *Client) DeleteTable(table Table) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)

	ct := cPfrTable(table)
	pt.pfrio_buffer = unsafe.Pointer(&ct)
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_table)
	pt.pfrio_size = 1

	return ioctlTableDel(c.fd, &pt)
}

// ListTables returns all tables in the given anchor (empty string for root).
func (c *Client) ListTables(anchor string) ([]Table, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)

	if anchor != "" {
		copyStringToC(&pt.pfrio_table.pfrt_anchor[0], anchor, C.MAXPATHLEN)
	}
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_table)

	// First call: get count
	pt.pfrio_size = 0
	pt.pfrio_buffer = nil
	if err := ioctlTableGet(c.fd, &pt); err != nil {
		return nil, err
	}

	count := int(pt.pfrio_size)
	if count == 0 {
		return nil, nil
	}

	// Allocate buffer and get tables
	buf := C.calloc(C.size_t(count), C.size_t(C.sizeof_struct_pfr_table))
	if buf == nil {
		return nil, &OpError{Op: "ListTables", Err: ErrInvalidArgument}
	}
	defer C.free(buf)

	pt.pfrio_buffer = buf
	pt.pfrio_size = C.int(count)

	if err := ioctlTableGet(c.fd, &pt); err != nil {
		return nil, err
	}

	tables := make([]Table, int(pt.pfrio_size))
	for i := range tables {
		ct := (*C.struct_pfr_table)(unsafe.Add(buf, i*int(C.sizeof_struct_pfr_table)))
		tables[i] = goTable(ct)
	}

	return tables, nil
}

// AddTableAddresses adds addresses to a PF table.
func (c *Client) AddTableAddresses(table Table, addrs []TableAddress) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	return c.tableAddrOp(ioctlTableAddAddrs, table, addrs)
}

// DeleteTableAddresses removes addresses from a PF table.
func (c *Client) DeleteTableAddresses(table Table, addrs []TableAddress) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	return c.tableAddrOp(ioctlTableDelAddrs, table, addrs)
}

// ReplaceTableAddresses atomically replaces all addresses in a PF table.
func (c *Client) ReplaceTableAddresses(table Table, addrs []TableAddress) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	return c.tableAddrOp(ioctlTableSetAddrs, table, addrs)
}

// ListTableAddresses returns all addresses in a PF table.
func (c *Client) ListTableAddresses(table Table) ([]TableAddress, error) {
	if err := ValidateTableName(table.Name); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)

	pt.pfrio_table = cPfrTable(table)
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_addr)

	// First call: get count
	pt.pfrio_size = 0
	pt.pfrio_buffer = nil
	if err := ioctlTableGetAddrs(c.fd, &pt); err != nil {
		return nil, err
	}

	count := int(pt.pfrio_size)
	if count == 0 {
		return nil, nil
	}

	buf := C.calloc(C.size_t(count), C.size_t(C.sizeof_struct_pfr_addr))
	if buf == nil {
		return nil, &OpError{Op: "ListTableAddresses", Err: ErrInvalidArgument}
	}
	defer C.free(buf)

	pt.pfrio_buffer = buf
	pt.pfrio_size = C.int(count)

	if err := ioctlTableGetAddrs(c.fd, &pt); err != nil {
		return nil, err
	}

	result := make([]TableAddress, int(pt.pfrio_size))
	for i := range result {
		ca := (*C.struct_pfr_addr)(unsafe.Add(buf, i*int(C.sizeof_struct_pfr_addr)))
		result[i] = goTableAddress(ca)
	}

	return result, nil
}

// TestTableAddress tests whether an IP is in the given table.
func (c *Client) TestTableAddress(table Table, addr net.IP) (bool, error) {
	if err := ValidateTableName(table.Name); err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return false, err
	}

	ta := TableAddress{IP: addr}
	ca := cPfrAddr(ta)

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)
	pt.pfrio_table = cPfrTable(table)
	pt.pfrio_buffer = unsafe.Pointer(&ca)
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_addr)
	pt.pfrio_size = 1

	if err := ioctlTableTstAddrs(c.fd, &pt); err != nil {
		return false, err
	}

	// After DIOCRTSTADDRS, pfra_fback indicates match
	return ca.pfra_fback == C.PFR_FB_MATCH, nil
}

// FlushTable removes all addresses from a PF table.
func (c *Client) FlushTable(table Table) error {
	if err := ValidateTableName(table.Name); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return err
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)
	pt.pfrio_table = cPfrTable(table)

	return ioctlTableClrAddrs(c.fd, &pt)
}

type tableIoctlFunc func(int, *C.struct_pfioc_table) error

func (c *Client) tableAddrOp(fn tableIoctlFunc, table Table, addrs []TableAddress) error {
	cAddrs := make([]C.struct_pfr_addr, len(addrs))
	for i, a := range addrs {
		cAddrs[i] = cPfrAddr(a)
	}

	var pt C.struct_pfioc_table
	C.memset(unsafe.Pointer(&pt), 0, C.sizeof_struct_pfioc_table)
	pt.pfrio_table = cPfrTable(table)
	pt.pfrio_buffer = unsafe.Pointer(&cAddrs[0])
	pt.pfrio_esize = C.int(C.sizeof_struct_pfr_addr)
	pt.pfrio_size = C.int(len(addrs))

	return fn(c.fd, &pt)
}
