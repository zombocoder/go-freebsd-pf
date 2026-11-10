# Contributing to go-freebsd-pf

Thanks for your interest in improving the library! Bug reports, fixes, new
PF operations, tests, examples and documentation are all welcome.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems should be reported privately, see [SECURITY.md](SECURITY.md).

## Table of Contents

- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [Safety Rules for PF Tests](#safety-rules-for-pf-tests)
- [Writing Tests](#writing-tests)
- [Continuous Integration](#continuous-integration)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Architecture Overview](#architecture-overview)
- [Where Help Is Wanted](#where-help-is-wanted)

## Getting Started

### Prerequisites

- FreeBSD 14.x or 15.x, amd64 or arm64 (13.x is end of life and untested)
- Go 1.22+ (`pkg install go`)
- The base system C compiler (cgo); `<net/pfvar.h>` and libnv come with base
- `pf.ko` loaded (`kldload pf`) for integration tests
- Root (or `doas`) for integration tests and for the examples

The integration tests change firewall state. A FreeBSD virtual machine you
can reach from a console is the most comfortable setup; never run the
PF-enabling tests on a machine whose firewall you depend on.

Unit tests (validation, error mapping, state filtering, byte order) also run
on macOS and Linux, where every `Client` method returns
`ErrUnsupportedPlatform`.

### Setup

```sh
git clone https://github.com/<your-username>/go-freebsd-pf.git
cd go-freebsd-pf
make build
make test
```

`make help` lists all targets. The Makefile works with FreeBSD's `make` and
with GNU make.

## Running Tests

| Command | Runs as | What it covers |
|---|---|---|
| `make test` | any user, any OS | Unit tests. Integration tests are not compiled (build tag `integration`). |
| `doas make test-integration` | root, FreeBSD | Unit tests plus integration tests that work inside test anchors and tables. Tests that need PF enabled skip themselves. |
| `doas make test-integration-pf` | root, FreeBSD test VM | Everything, including tests that enable PF (`GOPF_TEST_ENABLE_PF=1`). |

Running a subset works the usual way:

```sh
doas env GOPF_TEST_ENABLE_PF=1 go test -tags integration -count=1 -run KillStates -v ./pf
```

The integration test log prints which ioctl each version-dependent operation
uses in that build (`ioctls in this build: ...`).

## Safety Rules for PF Tests

A test that gets PF wrong can cut off the machine it runs on. Integration
tests therefore follow these rules, and new tests must too:

- **Anchors only.** Rules go into anchors under `go-freebsd-pf-test`
  (`go-freebsd-pf-test/rules`, `go-freebsd-pf-test/states`, ...), tables into
  that anchor. Never load, flush or modify the main ruleset directly.
- **Enabling PF is opt-in.** Only `enableSafePF` may enable PF. It skips
  unless `GOPF_TEST_ENABLE_PF=1` is set, PF is disabled and the main filter
  and NAT rulesets are empty. It then loads exactly

  ```
  anchor "go-freebsd-pf-test/*"
  pass all no state
  ```

  which passes all traffic (it cannot block ssh) and creates states only for
  rules a test puts into a test anchor, enables PF, and on cleanup disables
  PF and flushes the main ruleset, restoring "disabled, no ruleset".
- **Own interfaces only.** Traffic is generated on tap interfaces the test
  creates (`createTap`, kernel-assigned names) and destroys, with the
  198.18.254.0/30 benchmark range. Never use or modify existing interfaces
  (`re0`, `em0`, `vtnet0`, `bridge0`, ...).
- **Kill and clear by interface.** State tests remove only states on their
  own tap; never call `KillStates`/`ClearStates` with an empty filter.
- **Clean up on failure.** Use `t.Cleanup`/`defer` for anchors, tables, taps
  and states so a failing test leaves nothing behind.
- **Order:** call `enableSafePF` before `createTap`, so a skipped test
  creates nothing and cleanup tears the tap down before PF is disabled.
- **Safety net.** `TestMain` (in `pf/integration_states_test.go`) destroys
  leftover test taps, flushes the test anchors and, if a test enabled PF,
  disables it and flushes the main ruleset, after the run and on
  SIGINT/SIGTERM (Ctrl-C). A panic or a `go test -timeout` expiry kills the
  process before that can run and **can leave PF enabled** with the
  pass-all ruleset. Check with `pfctl -s info` and restore with
  `pfctl -d; pfctl -F rules`. This is one more reason to run the
  PF-enabling tests in a VM only.

## Writing Tests

- **Test first.** Write a test that fails for the right reason, then the fix.
- **Compare with pfctl.** Where possible, check results with `pfctl`
  (`pfctl -a <anchor> -sr`, `pfctl -ss -i <if>`) rather than only with the
  library's own getters, so a wrong ioctl or struct layout cannot hide behind
  a matching wrong reader.
- **Keep logic portable.** Pure Go logic (filters, conversions, error
  mapping) belongs in files without build tags so it is unit-tested on every
  OS; only the ioctl calls and C struct access need `freebsd && cgo`.
- **Gate** integration tests with the `integration` build tag and
  `openClient(t)` (which skips unless root).

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push to
`main` and every pull request:

- **Lint** (Linux): `gofmt` and `go mod tidy -diff`.
- **FreeBSD 14.5 and 15.1** (QEMU VMs via
  [vmactions/freebsd-vm](https://github.com/vmactions/freebsd-vm)): installs
  Go, loads `pf.ko`, runs `go vet` (with and without the `integration` tag),
  builds the package and examples, and runs the unit and integration tests
  as root with `GOPF_TEST_ENABLE_PF=1`. The VM is thrown away afterwards, so
  enabling PF there is safe. On 14.5 the integration suite runs a second
  time with `CGO_CFLAGS=-DGOPF_FORCE_NV`, so both ioctl paths are tested
  on the same kernel; 15.1 covers the nvlist path natively.
- Not covered: 13.x, 14.0–14.4, 15.0, and 15.x kernels without
  `COMPAT_FREEBSD14` (the CI images run GENERIC).

## Code Style

### Go

- Standard Go conventions; `gofmt` is enforced by CI (`make fmt-check`).
- Doc comments on all exported identifiers.
- Errors from ioctls are `*OpError` values; keep the sentinels
  (`ErrPermissionDenied`, `ErrNotSupported`, ...) reachable with `errors.Is`.
- Validate input (anchor, table and interface names, labels, ports) before
  issuing an ioctl.

### cgo

- C helpers live in the cgo preamble of the file that uses them; shared ioctl
  wrappers are in `pf/cgo_freebsd.go`.
- **Version differences are resolved in C at compile time** from the macros
  `<net/pfvar.h>` defines (`#if defined(DIOCGETSTATUS)`), not from
  `__FreeBSD_version` and not with Go build tags (there are none per
  release). Keep both branches producing the same C struct so the Go side
  stays version-independent, and update `docs/compatibility.md` and
  `FEATURES.md`.
- **nvlist ioctls** use base's libnv. `nvlist_get_*` aborts on a missing key,
  so read through the `gopf_nv_*` helpers that check first. Take key layouts
  from `sys/netpfil/pf/pf_nv.c` / `pf_ioctl.c` of the release you target.
- **Memory**: every `C.CString`/`C.malloc`/`nvlist_create` has a matching
  free/destroy, also on error paths; preserve `errno` across cleanup.
- **Pointers**: never store a Go pointer inside a struct passed to the kernel
  (cgo pointer rules); allocate such buffers in C (see `transaction.go`).
- Unions show up in Go as byte arrays; access them through C helpers.
- When in doubt, check how `sbin/pfctl` and `lib/libpfctl` issue the request
  on the target release.

## Submitting Changes

1. Create a branch from `main`.
2. Make the change with tests; update doc comments, README, `FEATURES.md`
   and examples when the public API changes, and add an entry to
   [CHANGELOG.md](CHANGELOG.md) under "Unreleased".
3. Run `make check` and `doas make test-integration` on FreeBSD (and
   `test-integration-pf` in a VM if you touched PF on/off or states).
4. Open a pull request; the template has a short checklist. CI must be green.

Commit messages: a short summary line, a blank line, then what changed and
why (which ioctl, which release, what the kernel does).

### Scope

- The library is FreeBSD-specific by design; cross-platform layers are out of
  scope.
- It talks to the kernel directly. Shelling out to `pfctl` is only
  acceptable in tests.
- Avoid breaking public API changes; when one is unavoidable, call it out in
  the pull request and in the changelog.

## Architecture Overview

```
pf/
  client.go          Client, Open/Close
  types.go           Rule, Table, State, Status, ... (pure Go)
  status.go          Enable, Disable, Status, ClearStatus
  rules.go           ListRules, ReplaceRules, ClearRules
  transaction.go     Begin/AddRule/Commit/Rollback (DIOCX*)
  anchors.go         ListAnchors
  tables.go          Tables and table addresses
  states.go          ListStates, ClearStates, KillStates
  convert.go         Go <-> C struct conversion
  cgo_freebsd.go     ioctl wrappers, per-release ioctl selection, nvlist code
  filter.go          State filtering and byte-order helpers (pure Go)
  validate.go        Rule validation (pure Go)
  errors.go          OpError, sentinels, errno mapping (pure Go)
  unsupported.go     Stubs for non-FreeBSD / no-cgo builds
  integration*_test.go  Root-only tests (build tag "integration")
docs/                Design, ioctl notes, compatibility matrix
examples/            Example programs
.github/             CI workflow, issue and PR templates
```

### Adding an operation

1. **ioctl wrapper** in `pf/cgo_freebsd.go` (or the file's preamble): build
   the request as pfctl/libpfctl does. If the ioctl differs between
   releases, select it in the preamble from the header macros.
2. **Public API** on `Client`: documented, validated, `checkClosed`, errors
   through `ioctlErr`. Add the stub to `unsupported.go`.
3. **Tests**: unit tests for any pure Go logic, an integration test that
   checks the effect with `pfctl` while following the safety rules above.
4. **Docs**: README / `FEATURES.md` / `docs/compatibility.md`, an example
   if useful, and the changelog.

## Where Help Is Wanted

- **Netlink** (`<netpfil/pf/pf_nl.h>`) for FreeBSD 15 kernels without
  `COMPAT_FREEBSD14`: start/stop and state listing
- **Standalone `Client.AddRule`** (currently rejected by the kernel outside a
  transaction) and `DIOCCHANGERULE`-based insert/remove
- **NAT/RDR** rules with address pools, and more rule options (tags,
  `max-states`, timeouts, `route-to`)
- **Source nodes**, limits and timeouts
- **Testing on 13.x and on 15.x kernels without `COMPAT_FREEBSD14`** (not covered by CI)

Questions and design discussions are welcome in GitHub issues.
