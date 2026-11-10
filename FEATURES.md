# go-freebsd-pf Features

What the library supports, and which kernel interface each operation uses on
each FreeBSD release. All operations live in package `pf` and go through
`/dev/pf` ioctls (cgo); nothing shells out to `pfctl`.

Legend: ✅ works, ⚠️ works with a condition (see note), ❌ not available.
"15.x" was tested on 15.1-RELEASE (GENERIC, amd64); CI also runs 14.5.

## Client

| Function                     | 13.x / 14.x | 15.x |
|------------------------------|:-----------:|:----:|
| `Open(Options)`, `OpenDefault()`, `Close()`, `FD()` | ✅ | ✅ |

## PF on/off and status

| Function        | 13.x / 14.x            | 15.x                                   |
|-----------------|------------------------|----------------------------------------|
| `Enable()`      | ✅ `DIOCSTART`          | ⚠️ `DIOCSTART`, needs `COMPAT_FREEBSD14` |
| `Disable()`     | ✅ `DIOCSTOP`           | ⚠️ `DIOCSTOP`, needs `COMPAT_FREEBSD14`  |
| `Status()`      | ✅ `DIOCGETSTATUS`      | ✅ `DIOCGETSTATUSNV`                    |
| `IsEnabled()`   | ✅ (via `Status`)       | ✅ (via `Status`)                       |
| `ClearStatus()` | ✅ `DIOCCLRSTATUS`      | ✅ `DIOCCLRSTATUS`                      |

`Status` returns running flag, since, debug level, host id, status interface,
state and source-node counts, the PFRES counters (`pfctl -s info` "Counters"),
state-table search/insert/removal counters and the ruleset checksum.

## Rules and anchors

| Function                          | 13.x / 14.x                  | 15.x                           |
|-----------------------------------|------------------------------|--------------------------------|
| `ListRules(RuleQuery)`            | ✅ `DIOCGETRULES` + `DIOCGETRULE` | ✅ `DIOCGETRULES` + `DIOCGETRULENV` |
| `Begin(anchor, rulesets...)`, `Transaction.AddRule/Commit/Rollback` | ✅ `DIOCXBEGIN`, `DIOCBEGINADDRS`, `DIOCADDRULE`, `DIOCXCOMMIT`/`DIOCXROLLBACK` | ✅ same |
| `ReplaceRules(anchor, rules)`     | ✅ (transaction)              | ✅ (transaction)                |
| `ClearRules(anchor, ruleset)`     | ✅ (empty transaction)        | ✅ (empty transaction)          |
| `ListAnchors(path)`               | ✅ `DIOCGETRULESETS`/`DIOCGETRULESET` | ✅ same                 |
| `Client.AddRule(rule)`            | ❌ see note                   | ❌ see note                     |
| `ValidateRule`, `ValidateTableName` | ✅ (pure Go)               | ✅ (pure Go)                    |

Rule fields: action (pass/block/match), direction, interface, protocol,
address family, source/destination as address, CIDR, table or any (with
negation), port operators and ranges, quick, log, keep state, label, anchor.
`ListRules` also returns the rule number and per-rule evaluations, packets
and bytes. `ListRules` on an anchor that does not exist returns no rules.

Note: `Client.AddRule` issues `DIOCADDRULE` outside a transaction, which the
kernel rejects (`EINVAL` on 15.1; the add-rule path requires a transaction ticket on 13.x/14.x too); use `ReplaceRules` or
`Begin`/`Transaction.AddRule`/`Commit`.

## Tables

| Function                                   | 13.x / 14.x | 15.x |
|--------------------------------------------|:-----------:|:----:|
| `CreateTable`, `DeleteTable`, `ListTables` | ✅ `DIOCRADDTABLES`/`DIOCRDELTABLES`/`DIOCRGETTABLES` | ✅ same |
| `AddTableAddresses`, `DeleteTableAddresses`, `ReplaceTableAddresses`, `ListTableAddresses`, `TestTableAddress`, `FlushTable` | ✅ `DIOCR*ADDRS` | ✅ same |

## States

| Function                    | 13.x / 14.x          | 15.x                                            |
|-----------------------------|----------------------|-------------------------------------------------|
| `ListStates(StateFilter)`   | ✅ `DIOCGETSTATESV2`  | ⚠️ `DIOCGETSTATESV2`, needs `COMPAT_FREEBSD14`   |
| `KillStates(StateFilter)`   | ✅ `DIOCKILLSTATES`   | ✅ `DIOCKILLSTATESNV`                            |
| `ClearStates(StateFilter)`  | ✅ `DIOCCLRSTATES`    | ✅ `DIOCCLRSTATESNV`                             |

`StateFilter` selects by interface, source and destination network and (for
kill/clear) rule label. The interface criterion matches the interface a state
was created on, also for floating states (bound to `all`), so
`KillStates(StateFilter{Interface: "tap0"})` removes everything created on
`tap0` — the operation a VM manager needs when it destroys a guest's tap.
`State` carries id, creator id, `Interface` / `OrigInterface`, protocol,
direction, address family, source/destination address and port (initiator
first), packet and byte counters, age and time to expiry.

## FreeBSD 15 without COMPAT_FREEBSD14

GENERIC kernels include `options COMPAT_FREEBSD14`
(`sysctl kern.features.compat_freebsd14` is 1). On a custom 15.x kernel
without it, the operations marked ⚠️ return an error matching
`pf.ErrNotSupported`; everything else works. Netlink (`PFNL_CMD_*`), which
base's pfctl uses on 15, is not implemented.

## Errors

`OpError` (operation, errno, sentinel) with sentinels reachable through
`errors.Is`: `ErrPermissionDenied`, `ErrDeviceNotFound`, `ErrAlreadyEnabled`,
`ErrAlreadyDisabled`, `ErrInvalidArgument`, `ErrInvalidRule`,
`ErrTransactionClosed`, `ErrTableNotFound`, `ErrNotSupported`,
`ErrUnsupportedPlatform` (every call on non-FreeBSD or without cgo).

## Not implemented

NAT/RDR/BINAT rule fields (pools, redirections), scrub options, ALTQ/queues,
source nodes, timeouts and limits, interface flags (`set skip`), Ethernet
(layer 2) rules, OS fingerprints, and netlink.
