# PF ioctl Technical Notes

This document describes the PF ioctls used by go-freebsd-pf. All ioctls operate on a file descriptor opened from `/dev/pf` and are defined in `<net/pfvar.h>`.

## DIOCSTART / DIOCSTOP

Enable or disable PF. These take no arguments (the ioctl argument is ignored). Returns EACCES if the caller lacks permission, or EEXIST/ENOENT if PF is already in the requested state.

## DIOCGETSTATUS

Retrieves PF status information. Takes a pointer to `struct pf_status` (defined in `<netpfil/pf/pf.h>`, re-exported via `<net/pfvar.h>`).

Key fields:
- `running` -- 1 if PF is enabled, 0 otherwise
- `since` -- Unix timestamp of when PF was last enabled
- `states` -- current number of entries in the state table
- `src_nodes` -- current number of source tracking nodes
- `debug` -- current debug level
- `hostid` -- host identifier
- `ifname` -- status interface name
- `counters[]` -- packet/byte counters indexed by PFRES_* constants
- `lcounters[]` -- limit counters indexed by LCNT_* constants
- `fcounters[]` -- state search counters indexed by FCNT_* constants
- `scounters[]` -- source node counters indexed by SCNT_* constants
- `pf_chksum[]` -- 16-byte MD5 checksum of the active ruleset

## DIOCGETRULES / DIOCGETRULE

Retrieve rules using ticket-based iteration.

**DIOCGETRULES** takes a `struct pfioc_rule` with the `anchor` field set and `rule.action` set to indicate the ruleset (PF_PASS for filter rules). The kernel fills in `nr` (total number of rules) and `ticket` (iteration ticket).

**DIOCGETRULE** takes the same struct with `ticket` and `nr` set to the index of the desired rule (0-based). The kernel fills in the `rule` field with the complete rule data.

Typical iteration pattern:
```
1. Set anchor and action in pfioc_rule
2. Call DIOCGETRULES to get count and ticket
3. For i = 0 to nr-1:
   a. Set pr.nr = i, keep ticket
   b. Call DIOCGETRULE
   c. Read rule from pr.rule
```

## DIOCADDRULE

Add a rule to a ruleset. Takes a `struct pfioc_rule` with the `rule` field populated and `ticket` set from a DIOCXBEGIN transaction. The `anchor` field specifies the target anchor (empty string for the main ruleset). The `pool_ticket` field should be set to 0 for simple rules.

## DIOCXBEGIN / DIOCXCOMMIT / DIOCXROLLBACK

Atomic transaction operations. All three take a `struct pfioc_trans`:

```c
struct pfioc_trans {
    int              size;    // number of elements
    int              esize;   // sizeof(struct pfioc_trans_e)
    struct pfioc_trans_e *array;
};

struct pfioc_trans_e {
    int              rs_num;  // ruleset number (PF_RULESET_*)
    char             anchor[MAXPATHLEN];
    u_int32_t        ticket;  // filled by kernel on XBEGIN
};
```

**DIOCXBEGIN** allocates new rulesets and returns tickets. The old rulesets remain active until commit.

**DIOCXCOMMIT** atomically swaps the new rulesets into the active position. Tickets must match what was returned by DIOCXBEGIN. Fails if any ticket is stale (another transaction was committed since).

**DIOCXROLLBACK** discards the pending rulesets and releases the tickets.

## DIOCR*TABLES / DIOCR*ADDRS

Table operations use `struct pfioc_table`:

```c
struct pfioc_table {
    struct pfr_table pfrio_table;
    void            *pfrio_buffer;
    int              pfrio_esize;
    int              pfrio_size;
    int              pfrio_size2;
    int              pfrio_nadd;
    int              pfrio_ndel;
    int              pfrio_nchange;
    int              pfrio_flags;
    u_int32_t        pfrio_ticket;
};
```

**Table management:**
- `DIOCRADDTABLES` -- create tables
- `DIOCRDELTABLES` -- delete tables
- `DIOCRGETTABLES` -- list tables (two-pass: first call with size=0 gets count, second call with allocated buffer gets data)

**Address management (within a table):**
- `DIOCRADDADDRS` -- add addresses to a table
- `DIOCRDELADDRS` -- remove addresses from a table
- `DIOCRSETADDRS` -- replace all addresses in a table
- `DIOCRGETADDRS` -- list addresses in a table (two-pass like DIOCRGETTABLES)
- `DIOCRTSTADDRS` -- test if addresses exist in a table
- `DIOCRCLRADDRS` -- clear all addresses from a table

Buffer entries are `struct pfr_addr` (for addresses) or `struct pfr_table` (for table listings). The `pfrio_esize` field must be set to `sizeof(struct pfr_addr)` or `sizeof(struct pfr_table)` respectively.

## DIOCGETSTATESV2

Retrieve state table entries. Takes a `struct pfioc_states_v2`. This ioctl uses a two-pass approach:

1. First call with `ps_len = 0`. The kernel sets `ps_len` to the required buffer size.
2. Allocate a buffer of `ps_len` bytes and set `ps_buf` to point to it.
3. Second call fills the buffer with `struct pf_state_export` entries.

The `pfioc_states_v2` struct contains an anonymous union for the buffer pointer, which requires a C helper function to access from Go (see note below on anonymous unions).

Each `struct pf_state_export` contains:
- `id` / `creatorid` -- state identifier
- `ifname` -- interface name
- `key[2]` -- wire and stack state keys, each containing addresses and ports
- `proto`, `af`, `direction` -- protocol information
- `packets[2]`, `bytes[2]` -- traffic counters (in/out)
- `creation`, `expire` -- timing information in seconds

Note: DIOCGETSTATESV2 was added in FreeBSD 14.0. Older versions only have DIOCGETSTATES (which uses a different struct layout).

## DIOCCLRSTATES / DIOCKILLSTATES

Clear or kill states matching a filter. Both take `struct pfioc_state_kill`:

```c
struct pfioc_state_kill {
    struct pf_rule_addr psk_src;
    struct pf_rule_addr psk_dst;
    char                psk_ifname[IFNAMSIZ];
    char                psk_label[PF_RULE_LABEL_SIZE];
    sa_family_t         psk_af;
    // ... additional fields
};
```

**DIOCCLRSTATES** clears all matching states. **DIOCKILLSTATES** also clears matching states but is designed for targeted removal. Both return the number of states killed via the ioctl return mechanism.

Setting all fields to zero matches all states (clears the entire state table).

## Notes on Anonymous Unions and cgo

cgo translates C unions into Go byte arrays (`[N]byte`). This means union members cannot be accessed directly from Go. The library uses static C helper functions defined in the cgo preamble to access union members. This affects:

- `pf_addr_wrap.v` -- union containing `struct { pf_addr addr; pf_addr mask; }` and `char tblname[PF_TABLE_NAME_SIZE]`
- `pfioc_states_v2.ps_buf` -- anonymous union containing the buffer pointer
- `pfr_addr.pfra_u` -- union containing IPv4 and IPv6 address storage

## Notes on NV (Name-Value) Variants

FreeBSD has been adding NV (nvlist-based) variants of PF ioctls:
- `DIOCGETSTATUSNV` -- NV variant of DIOCGETSTATUS
- Other NV ioctls are being added incrementally

The NV variants use `nvlist_t` serialization instead of fixed C structs, which provides better forward compatibility and versioning. These are the intended future direction for PF management interfaces in FreeBSD. This library currently uses the traditional struct-based ioctls for maximum compatibility across FreeBSD versions.
