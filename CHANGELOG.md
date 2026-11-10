# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- FreeBSD 15.x support. FreeBSD 15 removed `DIOCGETSTATUS`, `DIOCGETRULE`,
  `DIOCCLRSTATES` and `DIOCKILLSTATES` from `<net/pfvar.h>`; v0.1.0 did not
  compile there. The C preamble now picks each ioctl at compile time from the
  macros the header defines: the struct ioctls on 13.x/14.x (unchanged), the
  nvlist ioctls `DIOCGETSTATUSNV`, `DIOCGETRULENV`, `DIOCCLRSTATESNV` and
  `DIOCKILLSTATESNV` (through base's libnv) on 15.x. `Status`, `IsEnabled`,
  `ListRules`, `ClearStates` and `KillStates` (including by interface) work
  on 15.1. `CGO_CFLAGS=-DGOPF_FORCE_NV` selects the nvlist path on older
  releases. See `docs/compatibility.md` for the ioctl used per operation.
- On 15.x, `ListStates` uses `DIOCGETSTATESV2`, which the headers only expose
  to `COMPAT_FREEBSD14` kernels; GENERIC kernels serve it.
- `ErrNotSupported`: returned by `Enable`, `Disable` and `ListStates` when the
  kernel does not implement the ioctl (FreeBSD 15 without
  `options COMPAT_FREEBSD14`).
- `State.OrigInterface`: the interface a state was created on. For floating
  states (the default state-policy) `State.Interface` is `all`.
- Integration tests for status, rules in an anchor, and listing, killing and
  clearing states by interface. Tests that enable PF run only with
  `GOPF_TEST_ENABLE_PF=1` and only when PF is disabled with an empty main
  ruleset.
- GitHub Actions CI: gofmt and `go mod tidy` checks, and the unit and
  integration tests as root in FreeBSD 14.5 and 15.1 VMs under QEMU.
- Contributor documentation: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `FEATURES.md`, issue and pull request templates.

### Changed

- `ListRules` and `ListTables` on an anchor that does not exist (for example
  after `ClearRules` removed it) return an empty result instead of an
  `EINVAL` error.
- The Makefile follows the layout of go-freebsd-ifc (`make help`).
  `make test-integration` no longer runs `sudo` itself; run it as root.

### Fixed

- `Transaction.AddRule` (and so `ReplaceRules`) failed with "device busy"
  once anything, such as `pfctl -f /etc/pf.conf`, had used `DIOCBEGINADDRS`:
  `pool_ticket` was hard-coded to 0. It is now taken from `DIOCBEGINADDRS`.
- `ListRules` passes the requested ruleset to `DIOCGETRULE` as well, so the
  ticket from `DIOCGETRULES` always belongs to the same ruleset.
- `ListStates`: `Source`/`Destination` (and ports) were swapped for outbound
  states; `ID`, `CreatorID`, `Creation` and `Expire` were read in network byte
  order (`Expire` showed hundreds of thousands of hours).
- `ListStates` with `StateFilter{Interface: ...}` did not match floating
  states; it now matches `Interface` or `OrigInterface`, like the kernel does
  for `KillStates`/`ClearStates`.
- The package did not compile on non-FreeBSD hosts (missing import in the
  stub), so `go test ./...` failed on macOS and Linux.

## [0.1.0] - 2026-05-02

### Added

- Initial release: enable/disable and status, rules (list, add, replace,
  clear) with anchors, transactions, tables and table addresses, and state
  listing/clearing/killing through `/dev/pf` ioctls with cgo, for FreeBSD
  13.x and 14.x.

[Unreleased]: https://github.com/zombocoder/go-freebsd-pf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zombocoder/go-freebsd-pf/releases/tag/v0.1.0
