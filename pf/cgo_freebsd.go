//go:build freebsd && cgo

package pf

/*
#cgo freebsd CFLAGS: -D__BSD_VISIBLE
#cgo freebsd LDFLAGS: -lnv
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

// Mechanism selection, done at compile time from <net/pfvar.h>.
//
// FreeBSD 15 removed the fixed-struct DIOCGETSTATUS, DIOCGETRULE,
// DIOCCLRSTATES and DIOCKILLSTATES. Their nvlist variants (DIOC*NV) exist
// on every supported release (13.2+), so whenever the fixed-struct macro
// is missing the nvlist ioctl is used instead and its answer is copied
// into the same C struct the fixed-struct ioctl would have filled. The Go
// side does not care which one ran.
//
// Building with CGO_CFLAGS=-DGOPF_FORCE_NV selects the nvlist ioctls on
// 13.x/14.x too (useful to exercise that path on an older host).
#if defined(DIOCGETSTATUS) && !defined(GOPF_FORCE_NV)
#define GOPF_STATUS_NV 0
#else
#define GOPF_STATUS_NV 1
#endif
#if defined(DIOCGETRULE) && !defined(GOPF_FORCE_NV)
#define GOPF_RULE_NV 0
#else
#define GOPF_RULE_NV 1
#endif
#if defined(DIOCCLRSTATES) && defined(DIOCKILLSTATES) && !defined(GOPF_FORCE_NV)
#define GOPF_STATES_KILL_NV 0
#else
#define GOPF_STATES_KILL_NV 1
#endif

// FreeBSD 15 only declares DIOCGETSTATESV2 under COMPAT_FREEBSD14, a
// kernel option. The kernel still serves the ioctl when it is built with
// that option (GENERIC is), and struct pfioc_states_v2 / pf_state_export
// are still declared, so define the request ourselves. Kernels without
// the option answer ENODEV, which Go turns into ErrNotSupported.
#ifdef DIOCGETSTATESV2
#define GOPF_STATESV2_COMPAT 0
#else
#define GOPF_STATESV2_COMPAT 1
#define DIOCGETSTATESV2 _IOWR('D', 93, struct pfioc_states_v2)
#endif

#if GOPF_STATUS_NV || GOPF_RULE_NV || GOPF_STATES_KILL_NV
// nvlist ioctl plumbing (libnv). nvlist_get_* abort() on a missing key,
// so every read goes through a helper that checks existence first.

// gopf_nv_ioctl packs in, runs the pfioc_nv ioctl cmd and unpacks the
// kernel's answer into *out. Returns 0, or -1 with errno set.
static int gopf_nv_ioctl(int fd, unsigned long cmd, const nvlist_t *in,
    nvlist_t **out) {
	struct pfioc_nv nv;
	void *packed, *buf;
	size_t len, size;
	int err;

	*out = NULL;
	if (nvlist_error(in) != 0) {
		errno = nvlist_error(in);
		return -1;
	}
	packed = nvlist_pack(in, &len);
	if (packed == NULL)
		return -1;
	size = len < 4096 ? 4096 : len;
	for (;;) {
		buf = malloc(size);
		if (buf == NULL) {
			free(packed);
			errno = ENOMEM;
			return -1;
		}
		memcpy(buf, packed, len);
		nv.data = buf;
		nv.len = len;
		nv.size = size;
		if (ioctl(fd, cmd, &nv) == 0)
			break;
		err = errno;
		free(buf);
		// The kernel answers ENOSPC when the reply does not fit.
		if (err == ENOSPC && size < (64u << 20)) {
			size *= 2;
			continue;
		}
		free(packed);
		errno = err;
		return -1;
	}
	free(packed);
	*out = nvlist_unpack(nv.data, nv.len, 0);
	free(buf);
	if (*out == NULL) {
		errno = EBADMSG;
		return -1;
	}
	return 0;
}

static uint64_t gopf_nv_num(const nvlist_t *nvl, const char *name) {
	return nvlist_exists_number(nvl, name) ?
	    nvlist_get_number(nvl, name) : 0;
}

static bool gopf_nv_bool(const nvlist_t *nvl, const char *name) {
	return nvlist_exists_bool(nvl, name) && nvlist_get_bool(nvl, name);
}

static void gopf_nv_str(const nvlist_t *nvl, const char *name, char *dst,
    size_t size) {
	if (nvlist_exists_string(nvl, name))
		strlcpy(dst, nvlist_get_string(nvl, name), size);
}

static void gopf_nv_bin(const nvlist_t *nvl, const char *name, void *dst,
    size_t size) {
	const void *p;
	size_t n;

	if (!nvlist_exists_binary(nvl, name))
		return;
	p = nvlist_get_binary(nvl, name, &n);
	memcpy(dst, p, n < size ? n : size);
}

// gopf_nv_nums copies at most max entries of a number array.
static void gopf_nv_nums(const nvlist_t *nvl, const char *name,
    uint64_t *dst, size_t max) {
	const uint64_t *a;
	size_t n;

	if (!nvlist_exists_number_array(nvl, name))
		return;
	a = nvlist_get_number_array(nvl, name, &n);
	for (size_t i = 0; i < n && i < max; i++)
		dst[i] = a[i];
}

static const nvlist_t *gopf_nv_child(const nvlist_t *nvl, const char *name) {
	return nvlist_exists_nvlist(nvl, name) ?
	    nvlist_get_nvlist(nvl, name) : NULL;
}
#endif

#if GOPF_RULE_NV || GOPF_STATES_KILL_NV
// pf_rule_addr <-> nvlist, the layout of pf_nv.c's
// pf_rule_addr_to_nvrule_addr / pf_nvrule_addr_to_rule_addr.
static void gopf_nv_to_rule_addr(const nvlist_t *nvl, struct pf_rule_addr *ra) {
	const nvlist_t *aw, *a;
	uint64_t port[2] = { 0, 0 };

	if (nvl == NULL)
		return;
	if ((aw = gopf_nv_child(nvl, "addr")) != NULL) {
		ra->addr.type = gopf_nv_num(aw, "type");
		ra->addr.iflags = gopf_nv_num(aw, "iflags");
		switch (ra->addr.type) {
		case PF_ADDR_TABLE:
			gopf_nv_str(aw, "tblname", ra->addr.v.tblname,
			    sizeof(ra->addr.v.tblname));
			break;
		case PF_ADDR_DYNIFTL:
			gopf_nv_str(aw, "ifname", ra->addr.v.ifname,
			    sizeof(ra->addr.v.ifname));
			break;
		default:
			if ((a = gopf_nv_child(aw, "addr")) != NULL)
				gopf_nv_bin(a, "addr", &ra->addr.v.a.addr,
				    sizeof(ra->addr.v.a.addr));
			if ((a = gopf_nv_child(aw, "mask")) != NULL)
				gopf_nv_bin(a, "addr", &ra->addr.v.a.mask,
				    sizeof(ra->addr.v.a.mask));
			break;
		}
	}
	gopf_nv_nums(nvl, "port", port, 2);
	ra->port[0] = port[0];
	ra->port[1] = port[1];
	ra->neg = gopf_nv_num(nvl, "neg");
	ra->port_op = gopf_nv_num(nvl, "port_op");
}

static nvlist_t *gopf_rule_addr_to_nv(const struct pf_rule_addr *ra) {
	nvlist_t *nvl, *aw, *a;

	nvl = nvlist_create(0);
	aw = nvlist_create(0);
	nvlist_add_number(aw, "type", ra->addr.type);
	nvlist_add_number(aw, "iflags", ra->addr.iflags);
	if (ra->addr.type == PF_ADDR_TABLE)
		nvlist_add_string(aw, "tblname", ra->addr.v.tblname);
	if (ra->addr.type == PF_ADDR_DYNIFTL)
		nvlist_add_string(aw, "ifname", ra->addr.v.ifname);
	// The kernel always parses addr and mask, after the names, into the
	// same union. Sending the raw union bytes keeps the names intact.
	a = nvlist_create(0);
	nvlist_add_binary(a, "addr", &ra->addr.v.a.addr,
	    sizeof(ra->addr.v.a.addr));
	nvlist_move_nvlist(aw, "addr", a);
	a = nvlist_create(0);
	nvlist_add_binary(a, "addr", &ra->addr.v.a.mask,
	    sizeof(ra->addr.v.a.mask));
	nvlist_move_nvlist(aw, "mask", a);
	nvlist_move_nvlist(nvl, "addr", aw);
	nvlist_append_number_array(nvl, "port", ra->port[0]);
	nvlist_append_number_array(nvl, "port", ra->port[1]);
	nvlist_add_number(nvl, "neg", ra->neg);
	nvlist_add_number(nvl, "port_op", ra->port_op);
	return nvl;
}
#endif

// pf_get_status fills a struct pf_status.
#if GOPF_STATUS_NV
// DIOCGETSTATUSNV reply layout: pf_ioctl.c pf_getstatus().
static void gopf_nv_counters(const nvlist_t *nvl, const char *name,
    uint64_t *dst, size_t max) {
	const nvlist_t *c = gopf_nv_child(nvl, name);

	if (c != NULL)
		gopf_nv_nums(c, "counters", dst, max);
}

#define GOPF_NELEM(a) (sizeof(a) / sizeof((a)[0]))

static int pf_get_status(int fd, struct pf_status *s) {
	nvlist_t *in, *out;
	int rv, err;

	memset(s, 0, sizeof(*s));
	in = nvlist_create(0);
	rv = gopf_nv_ioctl(fd, DIOCGETSTATUSNV, in, &out);
	err = errno;
	nvlist_destroy(in);
	if (rv != 0) {
		errno = err;
		return -1;
	}
	s->running = gopf_nv_bool(out, "running");
	s->since = gopf_nv_num(out, "since");
	s->debug = gopf_nv_num(out, "debug");
	s->hostid = gopf_nv_num(out, "hostid");
	s->states = gopf_nv_num(out, "states");
	s->src_nodes = gopf_nv_num(out, "src_nodes");
	gopf_nv_counters(out, "counters", s->counters, GOPF_NELEM(s->counters));
	gopf_nv_counters(out, "lcounters", s->lcounters,
	    GOPF_NELEM(s->lcounters));
	gopf_nv_counters(out, "fcounters", s->fcounters,
	    GOPF_NELEM(s->fcounters));
	gopf_nv_counters(out, "scounters", s->scounters,
	    GOPF_NELEM(s->scounters));
	gopf_nv_nums(out, "pcounters", &s->pcounters[0][0][0],
	    sizeof(s->pcounters) / sizeof(uint64_t));
	gopf_nv_nums(out, "bcounters", &s->bcounters[0][0],
	    sizeof(s->bcounters) / sizeof(uint64_t));
	gopf_nv_str(out, "ifname", s->ifname, sizeof(s->ifname));
	gopf_nv_bin(out, "chksum", s->pf_chksum, sizeof(s->pf_chksum));
	nvlist_destroy(out);
	return 0;
}
#else
static int pf_get_status(int fd, struct pf_status *s) {
	return ioctl(fd, DIOCGETSTATUS, s);
}
#endif

// We wrap ioctl in static functions so cgo can capture errno properly.
// Each function returns 0 on success, -1 on failure (with errno set).

static int pf_start(int fd) {
	return ioctl(fd, DIOCSTART);
}

static int pf_stop(int fd) {
	return ioctl(fd, DIOCSTOP);
}

static int pf_clear_status(int fd) {
	return ioctl(fd, DIOCCLRSTATUS);
}

static int pf_get_rules(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCGETRULES, pr);
}

// pf_get_rule fills pr->rule for rule pr->nr of the ruleset selected by
// pr->anchor and pr->rule.action, using pr->ticket from DIOCGETRULES.
#if GOPF_RULE_NV
// DIOCGETRULENV request/reply layout: pf_ioctl.c and pf_nv.c
// pf_krule_to_nvrule(). Only the fields this package reads are copied.
static int pf_get_rule(int fd, struct pfioc_rule *pr) {
	nvlist_t *in, *out;
	const nvlist_t *r;
	uint64_t a[2];
	int rv, err;

	in = nvlist_create(0);
	nvlist_add_string(in, "anchor", pr->anchor);
	nvlist_add_number(in, "ruleset", pr->rule.action);
	nvlist_add_number(in, "ticket", pr->ticket);
	nvlist_add_number(in, "nr", pr->nr);
	rv = gopf_nv_ioctl(fd, DIOCGETRULENV, in, &out);
	err = errno;
	nvlist_destroy(in);
	if (rv != 0) {
		errno = err;
		return -1;
	}
	gopf_nv_str(out, "anchor_call", pr->anchor_call,
	    sizeof(pr->anchor_call));
	memset(&pr->rule, 0, sizeof(pr->rule));
	if ((r = gopf_nv_child(out, "rule")) == NULL) {
		nvlist_destroy(out);
		errno = EBADMSG;
		return -1;
	}
	pr->rule.nr = gopf_nv_num(r, "nr");
	gopf_nv_to_rule_addr(gopf_nv_child(r, "src"), &pr->rule.src);
	gopf_nv_to_rule_addr(gopf_nv_child(r, "dst"), &pr->rule.dst);
	gopf_nv_str(r, "label", pr->rule.label, sizeof(pr->rule.label));
	gopf_nv_str(r, "ifname", pr->rule.ifname, sizeof(pr->rule.ifname));
	gopf_nv_str(r, "tagname", pr->rule.tagname, sizeof(pr->rule.tagname));
	gopf_nv_str(r, "match_tagname", pr->rule.match_tagname,
	    sizeof(pr->rule.match_tagname));
	pr->rule.evaluations = gopf_nv_num(r, "evaluations");
	a[0] = a[1] = 0;
	gopf_nv_nums(r, "packets", a, 2);
	pr->rule.packets[0] = a[0];
	pr->rule.packets[1] = a[1];
	a[0] = a[1] = 0;
	gopf_nv_nums(r, "bytes", a, 2);
	pr->rule.bytes[0] = a[0];
	pr->rule.bytes[1] = a[1];
	pr->rule.rtableid = gopf_nv_num(r, "rtableid");
	pr->rule.max_states = gopf_nv_num(r, "max_states");
	pr->rule.rule_flag = gopf_nv_num(r, "rule_flag");
	pr->rule.return_icmp = gopf_nv_num(r, "return_icmp");
	pr->rule.return_icmp6 = gopf_nv_num(r, "return_icmp6");
	pr->rule.action = gopf_nv_num(r, "action");
	pr->rule.direction = gopf_nv_num(r, "direction");
	pr->rule.log = gopf_nv_num(r, "log");
	pr->rule.logif = gopf_nv_num(r, "logif");
	pr->rule.quick = gopf_nv_num(r, "quick");
	pr->rule.ifnot = gopf_nv_num(r, "ifnot");
	pr->rule.keep_state = gopf_nv_num(r, "keep_state");
	pr->rule.af = gopf_nv_num(r, "af");
	pr->rule.proto = gopf_nv_num(r, "proto");
	pr->rule.type = gopf_nv_num(r, "type");
	pr->rule.code = gopf_nv_num(r, "code");
	pr->rule.flags = gopf_nv_num(r, "flags");
	pr->rule.flagset = gopf_nv_num(r, "flagset");
	nvlist_destroy(out);
	return 0;
}
#else
static int pf_get_rule(int fd, struct pfioc_rule *pr) {
	return ioctl(fd, DIOCGETRULE, pr);
}
#endif

// pf_begin_addrs starts an (empty) pool address buffer and returns its
// ticket, which DIOCADDRULE wants in pool_ticket. The kernel compares it
// with its current pool-buffer ticket, so a hard-coded 0 only works until
// something else (pfctl -f) has used DIOCBEGINADDRS.
static int pf_begin_addrs(int fd, u_int32_t *ticket) {
	struct pfioc_pooladdr pp;
	int rv;

	memset(&pp, 0, sizeof(pp));
	rv = ioctl(fd, DIOCBEGINADDRS, &pp);
	*ticket = pp.ticket;
	return rv;
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

// pf_clear_states / pf_kill_states take the filter in psk and return the
// number of removed states in psk->psk_killed.
#if GOPF_STATES_KILL_NV
// DIOCCLRSTATESNV / DIOCKILLSTATESNV request layout: pf_nv.c
// pf_nvstate_kill_to_kstate_kill(); every key there is mandatory except
// rt_addr and nat. The reply carries "killed".
static int gopf_states_nv(int fd, unsigned long cmd,
    struct pfioc_state_kill *psk) {
	nvlist_t *in, *cmp, *out;
	int rv, err;

	in = nvlist_create(0);
	cmp = nvlist_create(0);
	nvlist_add_number(cmp, "id", psk->psk_pfcmp.id);
	nvlist_add_number(cmp, "creatorid", psk->psk_pfcmp.creatorid);
	nvlist_add_number(cmp, "direction", psk->psk_pfcmp.direction);
	nvlist_move_nvlist(in, "cmp", cmp);
	nvlist_add_number(in, "af", psk->psk_af);
	nvlist_add_number(in, "proto", psk->psk_proto);
	nvlist_move_nvlist(in, "src", gopf_rule_addr_to_nv(&psk->psk_src));
	nvlist_move_nvlist(in, "dst", gopf_rule_addr_to_nv(&psk->psk_dst));
	nvlist_add_string(in, "ifname", psk->psk_ifname);
	nvlist_add_string(in, "label", psk->psk_label);
	nvlist_add_bool(in, "kill_match", false);
	rv = gopf_nv_ioctl(fd, cmd, in, &out);
	err = errno;
	nvlist_destroy(in);
	if (rv != 0) {
		errno = err;
		return -1;
	}
	psk->psk_killed = gopf_nv_num(out, "killed");
	nvlist_destroy(out);
	return 0;
}

static int pf_clear_states(int fd, struct pfioc_state_kill *psk) {
	return gopf_states_nv(fd, DIOCCLRSTATESNV, psk);
}

static int pf_kill_states(int fd, struct pfioc_state_kill *psk) {
	return gopf_states_nv(fd, DIOCKILLSTATESNV, psk);
}
#else
static int pf_clear_states(int fd, struct pfioc_state_kill *psk) {
	return ioctl(fd, DIOCCLRSTATES, psk);
}

static int pf_kill_states(int fd, struct pfioc_state_kill *psk) {
	return ioctl(fd, DIOCKILLSTATES, psk);
}
#endif

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

// Set addr_wrap to dynamic interface type, as pfctl's dynaddr: the
// interface name, the modifier flags and a full host mask.
static void set_addr_wrap_dyn(struct pf_addr_wrap *aw, const char *ifname,
	u_int8_t iflags) {
	aw->type = PF_ADDR_DYNIFTL;
	aw->iflags = iflags;
	strlcpy(aw->v.ifname, ifname, IFNAMSIZ);
	memset(&aw->v.a.mask, 0xff, sizeof(aw->v.a.mask));
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

// Get interface name from addr_wrap (dynamic interface mode).
static const char* get_addr_wrap_ifname(const struct pf_addr_wrap *aw) {
	return aw->v.ifname;
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

// Names of the ioctls chosen at compile time (see the C preamble), used
// in errors so a failure names the request that actually ran.
var (
	opGetStatus   = pickOp(C.GOPF_STATUS_NV, "DIOCGETSTATUSNV", "DIOCGETSTATUS")
	opGetRule     = pickOp(C.GOPF_RULE_NV, "DIOCGETRULENV", "DIOCGETRULE")
	opClearStates = pickOp(C.GOPF_STATES_KILL_NV, "DIOCCLRSTATESNV", "DIOCCLRSTATES")
	opKillStates  = pickOp(C.GOPF_STATES_KILL_NV, "DIOCKILLSTATESNV", "DIOCKILLSTATES")
)

// statesV2Compat reports whether DIOCGETSTATESV2 had to be defined by
// this package because the headers only expose it to COMPAT_FREEBSD14
// kernels (FreeBSD 15).
const statesV2Compat = C.GOPF_STATESV2_COMPAT != 0

func pickOp(nv C.int, nvName, structName string) string {
	if nv != 0 {
		return nvName
	}
	return structName
}

// ioctlMechanisms lists the ioctl each version-dependent operation uses
// in this build.
func ioctlMechanisms() map[string]string {
	states := "DIOCGETSTATESV2"
	if statesV2Compat {
		states += " (COMPAT_FREEBSD14)"
	}
	return map[string]string{
		"Status":      opGetStatus,
		"ListRules":   "DIOCGETRULES + " + opGetRule,
		"ClearStates": opClearStates,
		"KillStates":  opKillStates,
		"ListStates":  states,
	}
}

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

// DIOCSTART and DIOCSTOP are only served by FreeBSD 15 kernels built with
// COMPAT_FREEBSD14 (pfctl itself uses netlink there); without it they
// report ErrNotSupported.

func ioctlStart(fd int) error {
	rv, err := C.pf_start(C.int(fd))
	return compatUnsupported(ioctlErr("DIOCSTART", rv, err))
}

func ioctlStop(fd int) error {
	rv, err := C.pf_stop(C.int(fd))
	return compatUnsupported(ioctlErr("DIOCSTOP", rv, err))
}

func ioctlGetStatus(fd int) (C.struct_pf_status, error) {
	var s C.struct_pf_status
	rv, err := C.pf_get_status(C.int(fd), &s)
	return s, ioctlErr(opGetStatus, rv, err)
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
	return ioctlErr(opGetRule, rv, err)
}

func ioctlBeginAddrs(fd int) (C.u_int32_t, error) {
	var ticket C.u_int32_t
	rv, err := C.pf_begin_addrs(C.int(fd), &ticket)
	return ticket, ioctlErr("DIOCBEGINADDRS", rv, err)
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
	return compatUnsupported(ioctlErr("DIOCGETSTATESV2", rv, err))
}

func ioctlClearStates(fd int, psk *C.struct_pfioc_state_kill) error {
	rv, err := C.pf_clear_states(C.int(fd), psk)
	return ioctlErr(opClearStates, rv, err)
}

func ioctlKillStates(fd int, psk *C.struct_pfioc_state_kill) error {
	rv, err := C.pf_kill_states(C.int(fd), psk)
	return ioctlErr(opKillStates, rv, err)
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

// setAddrWrapDyn sets a pf_addr_wrap to DYNIFTL type.
func setAddrWrapDyn(aw *C.struct_pf_addr_wrap, ifname string, flags IfaceFlags) {
	cstr := C.CString(ifname)
	defer C.free(unsafe.Pointer(cstr))
	C.set_addr_wrap_dyn(aw, cstr, C.u_int8_t(flags))
}

// getAddrWrapIfname extracts the interface name of a DYNIFTL pf_addr_wrap.
func getAddrWrapIfname(aw *C.struct_pf_addr_wrap) string {
	return C.GoString(C.get_addr_wrap_ifname(aw))
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
func cPfrTable(t Table) (C.struct_pfr_table, error) {
	var ct C.struct_pfr_table
	if err := copyStringToC(&ct.pfrt_name[0], "table name", t.Name, C.PF_TABLE_NAME_SIZE); err != nil {
		return ct, err
	}
	if err := copyStringToC(&ct.pfrt_anchor[0], "anchor", t.Anchor, C.MAXPATHLEN); err != nil {
		return ct, err
	}
	ct.pfrt_flags = C.u_int32_t(t.Flags)
	return ct, nil
}

// copyStringToC copies a Go string into a zeroed C char[size]. A string
// that does not fit with its NUL is rejected with ErrInvalidArgument
// instead of being truncated.
func copyStringToC(dst *C.char, field, src string, size C.int) error {
	if err := checkCString(field, src, int(size)); err != nil {
		return err
	}
	if len(src) == 0 {
		return nil
	}
	cstr := C.CString(src)
	defer C.free(unsafe.Pointer(cstr))
	C.strncpy(dst, cstr, C.size_t(len(src)))
	return nil
}
