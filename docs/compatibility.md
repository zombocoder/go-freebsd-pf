# FreeBSD Compatibility

## Supported Versions

| FreeBSD Version | Status    | Notes                                                        |
|-----------------|-----------|--------------------------------------------------------------|
| 13.2 – 13.5     | Supported | struct ioctls throughout                                     |
| 14.0 – 14.3     | Supported | struct ioctls throughout                                     |
| 15.0 – 15.1     | Supported | nvlist ioctls for status, rule read-back and state clear/kill; Enable/Disable and ListStates need a kernel with `COMPAT_FREEBSD14` (GENERIC has it) |

Tested on hardware: FreeBSD 15.1-RELEASE (GENERIC, amd64), unit and
integration tests. On 13.x/14.x the package selects the same ioctls
v0.1.0 used.

## How the ioctl is chosen

There is one build of the package; the choice is made at compile time by
the C preamble in `pf/cgo_freebsd.go`, from the macros `<net/pfvar.h>`
actually defines (not from `__FreeBSD_version`, so a release that keeps or
drops an ioctl is handled without a version table):

- If the struct ioctl macro exists (`DIOCGETSTATUS`, `DIOCGETRULE`,
  `DIOCCLRSTATES`/`DIOCKILLSTATES`), it is used (13.x, 14.x).
- Otherwise the nvlist variant is used (`DIOCGETSTATUSNV`, `DIOCGETRULENV`,
  `DIOCCLRSTATESNV`, `DIOCKILLSTATESNV`). These exist on every supported
  release (13.2 onwards), so `CGO_CFLAGS=-DGOPF_FORCE_NV` selects them on
  13.x/14.x as well. The request is built and the reply decoded with base's
  libnv (`-lnv`), and the reply is copied into the same C struct the struct
  ioctl fills, so the Go conversion code is shared by both paths.

The package links against libnv on every release; libnv is part of base.

## Mechanism per operation

| Operation                    | 13.x / 14.x                | 15.x                                       |
|------------------------------|----------------------------|--------------------------------------------|
| Enable / Disable             | DIOCSTART / DIOCSTOP       | DIOCSTART / DIOCSTOP (kernel: `COMPAT_FREEBSD14` only) |
| Status / IsEnabled           | DIOCGETSTATUS              | DIOCGETSTATUSNV                            |
| ClearStatus                  | DIOCCLRSTATUS              | DIOCCLRSTATUS                              |
| ListRules                    | DIOCGETRULES + DIOCGETRULE | DIOCGETRULES + DIOCGETRULENV               |
| Transactions, AddRule        | DIOCXBEGIN, DIOCBEGINADDRS, DIOCADDRULE, DIOCXCOMMIT | same             |
| ClearRules, ReplaceRules     | DIOCXBEGIN / DIOCXCOMMIT   | same                                       |
| ListAnchors                  | DIOCGETRULESETS / DIOCGETRULESET | same                                 |
| Tables                       | DIOCR*                     | same                                       |
| ClearStates                  | DIOCCLRSTATES              | DIOCCLRSTATESNV                            |
| KillStates                   | DIOCKILLSTATES             | DIOCKILLSTATESNV                           |
| ListStates                   | DIOCGETSTATESV2            | DIOCGETSTATESV2 (kernel: `COMPAT_FREEBSD14` only) |

### FreeBSD 15 details

- FreeBSD 15 removed `DIOCGETSTATUS`, `DIOCGETRULE`, `DIOCCLRSTATES` and
  `DIOCKILLSTATES` from `<net/pfvar.h>`; base's pfctl/libpfctl moved to
  netlink (`<netpfil/pf/pf_nl.h>`) for most operations. The kernel still
  serves the nvlist ioctls unconditionally.
- `DIOCGETSTATESV2` (and `DIOCGETSTATES`) are declared only under
  `#ifdef COMPAT_FREEBSD14`, and the kernel serves them only when built with
  `options COMPAT_FREEBSD14`. The structs (`pfioc_states_v2`,
  `pf_state_export`) are still declared, so the package defines the request
  itself. GENERIC kernels include the option
  (`sysctl kern.features.compat_freebsd14` reports 1).
- The kernel's `DIOCSTART`/`DIOCSTOP` handlers are likewise inside
  `#ifdef COMPAT_FREEBSD14` in `pf_ioctl.c` (pfctl uses netlink there).
- On a kernel without `COMPAT_FREEBSD14`, `Enable`, `Disable` and
  `ListStates` return an error that matches `pf.ErrNotSupported`
  (`errors.Is`). Everything else, including `KillStates`/`ClearStates` by
  interface, does not depend on the option. State listing without the
  compat ioctl is only possible through netlink (`PFNL_CMD_GETSTATES`),
  which this package does not implement.

### State filters and interfaces

With the default `set state-policy floating`, a state is bound to the
pseudo-interface `all`; the interface it was created on is
`State.OrigInterface`. `KillStates`/`ClearStates` with
`StateFilter{Interface: "tap0"}` remove states created on `tap0` in both
cases (the kernel matches the original interface), and `ListStates` with
the same filter matches `Interface` or `OrigInterface` the same way.

## Struct Layout Differences

PF structs defined in `<net/pfvar.h>` may have layout differences between FreeBSD major versions. Struct sizes, field offsets, and padding can change when PF internals are modified. Notable considerations:

- `struct pf_status` has had fields added and reordered across versions.
- `struct pf_rule` is large and complex; its layout is tied to the specific FreeBSD version.
- `struct pf_state_export` (`PF_STATE_VERSION` 20230404) is declared on 13.2 through 15.1.

Because the library uses cgo and compiles against the system's `<net/pfvar.h>`, the correct struct layouts are picked up at build time.

## Build Recommendations

- Always build on the same FreeBSD version where the binary will run. Cross-version deployment of cgo binaries that use kernel ioctl structs is not reliable, and a binary built on 14.x uses ioctls a 15.x kernel no longer has.
- Use `go build` on the target system, or set up a build environment matching the target FreeBSD version.
- The `freebsd-check` Makefile target verifies that the build host is running FreeBSD.

## CGO_ENABLED

cgo must be enabled for this library to compile. The build tags `freebsd` and `cgo` are both required. On FreeBSD, cgo is enabled by default when a C compiler is available. Verify with:

```
go env CGO_ENABLED
```

If it reports `0`, install a C compiler (cc/clang is included in the FreeBSD base system) and set `CGO_ENABLED=1`.
