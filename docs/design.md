# go-freebsd-pf Design

## Architecture

The library is organized into three layers:

1. **Public API** (`pf/client.go`, `pf/status.go`, `pf/rules.go`, `pf/tables.go`, `pf/states.go`, `pf/transaction.go`) -- Go types and methods that callers interact with. These accept and return pure Go types (net.IP, net.IPNet, and library-defined structs like Rule, Table, State, Status). No C types are exposed.

2. **Conversion layer** (`pf/convert.go`) -- Translates between Go types and C structs. Functions like `ruleToC` and `ruleFromC` handle the mapping. This layer also handles network byte order conversion for port numbers via `htons`/`ntohs`.

3. **cgo bindings** (`pf/cgo_freebsd.go`) -- Static C wrapper functions that invoke ioctl(2) on /dev/pf, plus helper functions for accessing C union members. Each ioctl is wrapped in its own C function so that cgo can properly capture errno.

## Why cgo Is Required

PF is controlled exclusively through ioctl(2) calls on the `/dev/pf` device file. These ioctls pass complex C structs defined in `<net/pfvar.h>` that contain nested unions, bitfields, and platform-specific type aliases (sa_family_t, u_int32_t, etc.). There is no text-based or socket-based protocol. The only practical way to construct these structs correctly from Go is through cgo, which gives access to the actual C type definitions and sizeof values from the running kernel headers.

Using raw syscall.Ioctl with manually computed struct layouts would be fragile, error-prone, and would break across FreeBSD versions when struct layouts change.

## Union Handling

cgo represents C unions as opaque byte arrays. This means Go code cannot directly access union members like `pf_addr_wrap.v.a.addr` or `pf_addr_wrap.v.tblname`. The library defines static C helper functions to read and write union members:

- `set_addr_wrap_addrmask` / `get_addr_wrap_addr` / `get_addr_wrap_mask` -- access the address/mask variant of `pf_addr_wrap.v.a`
- `set_addr_wrap_table` / `get_addr_wrap_tblname` -- access the table name variant of `pf_addr_wrap.v.tblname`
- `set_states_v2_buf` / `get_states_v2_buf` -- access the anonymous union in `pfioc_states_v2`

These helpers are defined as static inline functions in the cgo preamble and compiled into the Go binary.

## Thread Safety

The `Client` struct contains a `sync.Mutex` that is held during every ioctl call. This serializes all operations on a single /dev/pf file descriptor. Callers may use a Client from multiple goroutines without additional synchronization.

The `Transaction` struct has its own mutex and also acquires the client's mutex when performing ioctl calls, preventing interleaving of transaction operations with other client operations.

## Transaction Semantics

PF supports atomic ruleset replacement through a transaction mechanism:

1. **DIOCXBEGIN** -- Opens a transaction. The kernel returns a ticket for each ruleset included in the transaction. The old ruleset remains active.
2. Rules are added via **DIOCADDRULE** using the ticket from the transaction.
3. **DIOCXCOMMIT** -- Atomically replaces the old ruleset with the new one. If validation fails, the old ruleset remains unchanged.
4. **DIOCXROLLBACK** -- Discards the transaction without modifying the active ruleset.

The `pfioc_trans` struct contains an array of `pfioc_trans_e` elements, one per ruleset (filter, nat, rdr, etc.) included in the transaction. Each element specifies the ruleset number, anchor path, and receives a ticket from the kernel.

Transactions prevent partial ruleset updates. Either all rules in the transaction are applied, or none are.

## Network Byte Order

PF stores port numbers in network byte order (big-endian) within its structs. The conversion layer provides `htons` and `ntohs` functions to convert between host byte order and network byte order. These are implemented as simple byte swaps since Go always uses little-endian or big-endian host order consistently on a given platform. On FreeBSD/amd64 (little-endian), this swaps the two bytes of a uint16.

Port values in the public Go API (PortMatcher.From, PortMatcher.To, State.SourcePort, State.DestPort) are always in host byte order. The conversion happens transparently in the conversion layer.
