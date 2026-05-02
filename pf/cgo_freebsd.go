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
#include <errno.h>
#include <string.h>
#include <stdlib.h>

// We wrap ioctl in static functions so cgo can capture errno properly.
// Each function returns 0 on success, -1 on failure (with errno set).

static int pf_start(int fd) {
	return ioctl(fd, DIOCSTART);
}

static int pf_stop(int fd) {
	return ioctl(fd, DIOCSTOP);
}

static int pf_get_status(int fd, struct pf_status *s) {
	return ioctl(fd, DIOCGETSTATUS, s);
}

static int pf_clear_status(int fd) {
	return ioctl(fd, DIOCCLRSTATUS);
}

static int pf_get_rules(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCGETRULES, pr);
}

static int pf_get_rule(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCGETRULE, pr);
}

static int pf_add_rule(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCADDRULE, pr);
}

static int pf_change_rule(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCCHANGERULE, pr);
}

static int pf_xbegin(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXBEGIN, pt);
}

static int pf_xcommit(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXCOMMIT, pt);
}

static int pf_xrollback(int fd, struct pfioc_trans *pt) {
	return ioctl(fd, DIOCXROLLBACK, pt);
}

static int pf_table_add(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRADDTABLES, pt);
}

static int pf_table_del(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRDELTABLES, pt);
}

static int pf_table_get(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRGETTABLES, pt);
}

static int pf_table_add_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRADDADDRS, pt);
}

static int pf_table_del_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRDELADDRS, pt);
}

static int pf_table_set_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRSETADDRS, pt);
}

static int pf_table_get_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRGETADDRS, pt);
}

static int pf_table_tst_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRTSTADDRS, pt);
}

static int pf_table_clr_addrs(int fd, struct pfioc_table *pt) {
	return ioctl(fd, DIOCRCLRADDRS, pt);
}

static int pf_get_states_v2(int fd, struct pfioc_states_v2 *ps) {
	return ioctl(fd, DIOCGETSTATESV2, ps);
}

static int pf_clear_states(int fd, struct pfioc_state_kill *psk) {
	return ioctl(fd, DIOCCLRSTATES, psk);
}

static int pf_kill_states(int fd, struct pfioc_state_kill *psk) {
	return ioctl(fd, DIOCKILLSTATES, psk);
}

// Helper functions for pfioc_states_v2 anonymous union access.
static void set_states_v2_buf(struct pfioc_states_v2 *ps, void *buf) {
	ps->ps_buf = buf;
}

static void* get_states_v2_buf(struct pfioc_states_v2 *ps) {
	return ps->ps_buf;
}

// Helper functions to access union members in pf_addr_wrap,
// since cgo represents unions as byte arrays.

// Set addr_wrap to ADDRMASK type with addr and mask.
static void set_addr_wrap_addrmask(struct pf_addr_wrap *aw,
	const void *addr, const void *mask, int addrlen) {
	aw->type = PF_ADDR_ADDRMASK;
	if (addr)
		memcpy(&aw->v.a.addr, addr, addrlen);
	if (mask)
		memcpy(&aw->v.a.mask, mask, addrlen);
}

// Set addr_wrap to TABLE type.
static void set_addr_wrap_table(struct pf_addr_wrap *aw, const char *name) {
	aw->type = PF_ADDR_TABLE;
	strlcpy(aw->v.tblname, name, PF_TABLE_NAME_SIZE);
}

// Get addr bytes from addr_wrap (addrmask mode).
static void get_addr_wrap_addr(const struct pf_addr_wrap *aw,
	void *addr, int addrlen) {
	memcpy(addr, &aw->v.a.addr, addrlen);
}

// Get mask bytes from addr_wrap (addrmask mode).
static void get_addr_wrap_mask(const struct pf_addr_wrap *aw,
	void *mask, int addrlen) {
	memcpy(mask, &aw->v.a.mask, addrlen);
}

// Get table name from addr_wrap.
static const char* get_addr_wrap_tblname(const struct pf_addr_wrap *aw) {
	return aw->v.tblname;
}
*/
import "C"
import (
	"syscall"
	"unsafe"
)

// C type sizes
const (
	sizeofPfrAddr       = C.sizeof_struct_pfr_addr
	sizeofPfrTable      = C.sizeof_struct_pfr_table
	sizeofPfStateExport = C.sizeof_struct_pf_state_export
	sizeofPfiocTransE   = C.sizeof_struct_pfioc_trans_e
)

// ioctlErr converts a cgo C-function's return + errno into a Go error.
func ioctlErr(op string, rv C.int, err error) error {
	if rv == 0 {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok {
		return mapErrno(op, errno)
	}
	return &OpError{Op: op, Err: err}
}

// PF enable/disable/status ioctls

func ioctlStart(fd int) error {
	rv, err := C.pf_start(C.int(fd))
	return ioctlErr("DIOCSTART", rv, err)
}

func ioctlStop(fd int) error {
	rv, err := C.pf_stop(C.int(fd))
	return ioctlErr("DIOCSTOP", rv, err)
}

func ioctlGetStatus(fd int) (C.struct_pf_status, error) {
	var s C.struct_pf_status
	rv, err := C.pf_get_status(C.int(fd), &s)
	return s, ioctlErr("DIOCGETSTATUS", rv, err)
}

func ioctlClearStatus(fd int) error {
	rv, err := C.pf_clear_status(C.int(fd))
	return ioctlErr("DIOCCLRSTATUS", rv, err)
}

// Rule ioctls

func ioctlGetRules(fd int, pr *C.struct_pfioc_rule) error {
	rv, err := C.pf_get_rules(C.int(fd), pr)
	return ioctlErr("DIOCGETRULES", rv, err)
}

func ioctlGetRule(fd int, pr *C.struct_pfioc_rule) error {
	rv, err := C.pf_get_rule(C.int(fd), pr)
	return ioctlErr("DIOCGETRULE", rv, err)
}

func ioctlAddRule(fd int, pr *C.struct_pfioc_rule) error {
	rv, err := C.pf_add_rule(C.int(fd), pr)
	return ioctlErr("DIOCADDRULE", rv, err)
}

func ioctlChangeRule(fd int, pr *C.struct_pfioc_rule) error {
	rv, err := C.pf_change_rule(C.int(fd), pr)
	return ioctlErr("DIOCCHANGERULE", rv, err)
}

// Transaction ioctls

func ioctlXBegin(fd int, pt *C.struct_pfioc_trans) error {
	rv, err := C.pf_xbegin(C.int(fd), pt)
	return ioctlErr("DIOCXBEGIN", rv, err)
}

func ioctlXCommit(fd int, pt *C.struct_pfioc_trans) error {
	rv, err := C.pf_xcommit(C.int(fd), pt)
	return ioctlErr("DIOCXCOMMIT", rv, err)
}

func ioctlXRollback(fd int, pt *C.struct_pfioc_trans) error {
	rv, err := C.pf_xrollback(C.int(fd), pt)
	return ioctlErr("DIOCXROLLBACK", rv, err)
}

// Table ioctls

func ioctlTableAdd(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_add(C.int(fd), pt)
	return ioctlErr("DIOCRADDTABLES", rv, err)
}

func ioctlTableDel(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_del(C.int(fd), pt)
	return ioctlErr("DIOCRDELTABLES", rv, err)
}

func ioctlTableGet(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_get(C.int(fd), pt)
	return ioctlErr("DIOCRGETTABLES", rv, err)
}

func ioctlTableAddAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_add_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRADDADDRS", rv, err)
}

func ioctlTableDelAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_del_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRDELADDRS", rv, err)
}

func ioctlTableSetAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_set_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRSETADDRS", rv, err)
}

func ioctlTableGetAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_get_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRGETADDRS", rv, err)
}

func ioctlTableTstAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_tst_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRTSTADDRS", rv, err)
}

func ioctlTableClrAddrs(fd int, pt *C.struct_pfioc_table) error {
	rv, err := C.pf_table_clr_addrs(C.int(fd), pt)
	return ioctlErr("DIOCRCLRADDRS", rv, err)
}

// State ioctls

func ioctlGetStatesV2(fd int, ps *C.struct_pfioc_states_v2) error {
	rv, err := C.pf_get_states_v2(C.int(fd), ps)
	return ioctlErr("DIOCGETSTATESV2", rv, err)
}

func ioctlClearStates(fd int, psk *C.struct_pfioc_state_kill) error {
	rv, err := C.pf_clear_states(C.int(fd), psk)
	return ioctlErr("DIOCCLRSTATES", rv, err)
}

func ioctlKillStates(fd int, psk *C.struct_pfioc_state_kill) error {
	rv, err := C.pf_kill_states(C.int(fd), psk)
	return ioctlErr("DIOCKILLSTATES", rv, err)
}

// C helper wrappers for struct access

// setAddrWrapAddrmask sets a pf_addr_wrap to ADDRMASK type.
func setAddrWrapAddrmask(aw *C.struct_pf_addr_wrap, addr, mask []byte) {
	var addrPtr, maskPtr unsafe.Pointer
	if len(addr) > 0 {
		addrPtr = unsafe.Pointer(&addr[0])
	}
	if len(mask) > 0 {
		maskPtr = unsafe.Pointer(&mask[0])
	}
	addrlen := len(addr)
	if addrlen == 0 {
		addrlen = 16
	}
	C.set_addr_wrap_addrmask(aw, addrPtr, maskPtr, C.int(addrlen))
}

// setAddrWrapTable sets a pf_addr_wrap to TABLE type.
func setAddrWrapTable(aw *C.struct_pf_addr_wrap, name string) {
	cstr := C.CString(name)
	defer C.free(unsafe.Pointer(cstr))
	C.set_addr_wrap_table(aw, cstr)
}

// getAddrWrapAddr extracts address bytes from a pf_addr_wrap.
func getAddrWrapAddr(aw *C.struct_pf_addr_wrap, addrlen int) []byte {
	buf := make([]byte, addrlen)
	C.get_addr_wrap_addr(aw, unsafe.Pointer(&buf[0]), C.int(addrlen))
	return buf
}

// getAddrWrapMask extracts mask bytes from a pf_addr_wrap.
func getAddrWrapMask(aw *C.struct_pf_addr_wrap, addrlen int) []byte {
	buf := make([]byte, addrlen)
	C.get_addr_wrap_mask(aw, unsafe.Pointer(&buf[0]), C.int(addrlen))
	return buf
}

// getAddrWrapTblname extracts table name from a pf_addr_wrap.
func getAddrWrapTblname(aw *C.struct_pf_addr_wrap) string {
	return C.GoString(C.get_addr_wrap_tblname(aw))
}

// cPfrTable converts a Go Table to a C pfr_table.
func cPfrTable(t Table) C.struct_pfr_table {
	var ct C.struct_pfr_table
	copyStringToC(&ct.pfrt_name[0], t.Name, C.PF_TABLE_NAME_SIZE)
	copyStringToC(&ct.pfrt_anchor[0], t.Anchor, C.MAXPATHLEN)
	ct.pfrt_flags = C.u_int32_t(t.Flags)
	return ct
}

// copyStringToC copies a Go string into a C char array.
func copyStringToC(dst *C.char, src string, maxLen C.int) {
	if len(src) == 0 {
		return
	}
	n := len(src)
	if n >= int(maxLen) {
		n = int(maxLen) - 1
	}
	cstr := C.CString(src)
	defer C.free(unsafe.Pointer(cstr))
	C.strncpy(dst, cstr, C.size_t(n))
}
