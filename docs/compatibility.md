# FreeBSD Compatibility

## Supported Versions

| FreeBSD Version | Status    | Notes                                   |
|-----------------|-----------|------------------------------------------|
| 13.2            | Supported | DIOCGETSTATESV2 not available            |
| 13.3            | Supported | DIOCGETSTATESV2 not available            |
| 14.0            | Supported | DIOCGETSTATESV2 added                    |
| 14.1            | Supported | All ioctls available                     |
| 14.2            | Supported | All ioctls available                     |
| 14.3            | Supported | All ioctls available                     |

## ioctl Availability

The following ioctls are available on all supported FreeBSD versions (13.2+):

- DIOCSTART / DIOCSTOP
- DIOCGETSTATUS / DIOCCLRSTATUS
- DIOCGETRULES / DIOCGETRULE
- DIOCADDRULE / DIOCCHANGERULE
- DIOCXBEGIN / DIOCXCOMMIT / DIOCXROLLBACK
- DIOCRADDTABLES / DIOCRDELTABLES / DIOCRGETTABLES
- DIOCRADDADDRS / DIOCRDELADDRS / DIOCRSETADDRS / DIOCRGETADDRS / DIOCRTSTADDRS / DIOCRCLRADDRS
- DIOCCLRSTATES / DIOCKILLSTATES

### Version-Specific ioctls

**DIOCGETSTATESV2** was introduced in FreeBSD 14.0. On FreeBSD 13.x, this ioctl is not available. Code that calls state listing functions will fail at runtime on 13.x with an appropriate error. The older DIOCGETSTATES ioctl exists on 13.x but uses a different struct layout (`pfioc_states` with `pfsync_state` entries) that this library does not currently support.

## Struct Layout Differences

PF structs defined in `<net/pfvar.h>` may have layout differences between FreeBSD major versions. Struct sizes, field offsets, and padding can change when PF internals are modified. Notable considerations:

- `struct pf_status` has had fields added and reordered across versions.
- `struct pf_rule` is large and complex; its layout is tied to the specific FreeBSD version.
- `struct pf_state_export` was introduced alongside DIOCGETSTATESV2 in FreeBSD 14.0.

Because the library uses cgo and compiles against the system's `<net/pfvar.h>`, the correct struct layouts are picked up at build time.

## Build Recommendations

- Always build on the same FreeBSD version where the binary will run. Cross-version deployment of cgo binaries that use kernel ioctl structs is not reliable.
- Use `go build` on the target system, or set up a build environment matching the target FreeBSD version.
- The `freebsd-check` Makefile target verifies that the build host is running FreeBSD.

## CGO_ENABLED

cgo must be enabled for this library to compile. The build tags `freebsd` and `cgo` are both required. On FreeBSD, cgo is enabled by default when a C compiler is available. Verify with:

```
go env CGO_ENABLED
```

If it reports `0`, install a C compiler (cc/clang is included in the FreeBSD base system) and set `CGO_ENABLED=1`.
