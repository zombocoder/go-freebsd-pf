# go-freebsd-pf

[![CI](https://github.com/zombocoder/go-freebsd-pf/actions/workflows/ci.yml/badge.svg)](https://github.com/zombocoder/go-freebsd-pf/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zombocoder/go-freebsd-pf.svg)](https://pkg.go.dev/github.com/zombocoder/go-freebsd-pf)
[![Go Report Card](https://goreportcard.com/badge/github.com/zombocoder/go-freebsd-pf)](https://goreportcard.com/report/github.com/zombocoder/go-freebsd-pf)
[![Release](https://img.shields.io/github/v/release/zombocoder/go-freebsd-pf?sort=semver)](https://github.com/zombocoder/go-freebsd-pf/releases)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-green.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.22-00ADD8.svg)](https://golang.org/)
[![FreeBSD](https://img.shields.io/badge/FreeBSD-14%20%7C%2015-red.svg)](https://www.freebsd.org/)

A Go library for managing the FreeBSD PF (Packet Filter) firewall via /dev/pf ioctls.

This library provides a native Go interface to PF's kernel-level ioctl API, enabling programmatic control of firewall rules, tables, state tracking, and configuration from Go applications.

**This library only works on FreeBSD.** It requires cgo and root privileges.

**Tested in CI on:** FreeBSD 14.5 and 15.1 (amd64), with the integration
tests running as root in QEMU VMs. See [FEATURES.md](FEATURES.md) for what
each operation supports per release, the [changelog](CHANGELOG.md) and
[releases](https://github.com/zombocoder/go-freebsd-pf/releases).

## Requirements

- FreeBSD 14.x or 15.x (13.x untested)
- Go 1.22 or later
- cgo enabled (CGO_ENABLED=1)
- Root privileges (or appropriate /dev/pf permissions)
- A C compiler (clang is included in the FreeBSD base system)

## Installation

```
go get github.com/zombocoder/go-freebsd-pf
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/zombocoder/go-freebsd-pf/pf"
)

func main() {
    client, err := pf.OpenDefault()
    if err != nil {
        log.Fatal("Failed to open PF: ", err)
    }
    defer client.Close()

    status, err := client.Status()
    if err != nil {
        log.Fatal("Failed to get status: ", err)
    }

    fmt.Printf("PF running: %v\n", status.Running)
    fmt.Printf("Active states: %d\n", status.States)
}
```

## Features

- **Enable/Disable PF** -- Start and stop the packet filter
- **Status** -- Query PF status, counters, and debug level
- **Rules** -- List, add, and manage filter rules with full support for addresses, ports, protocols, and options
- **Tables** -- Create, delete, and manage PF tables and their address entries
- **States** -- List, clear, and kill state table entries with filtering support
- **Transactions** -- Atomic ruleset replacement via DIOCXBEGIN/DIOCXCOMMIT/DIOCXROLLBACK
- **Anchors** -- Operate on rules within named anchors
- **Address families** -- IPv4 and IPv6 support
- **Validation** -- Rule validation before submission to the kernel

## Supported FreeBSD Versions

| Version     | Support Level |
|-------------|---------------|
| 15.1        | Tested in CI. Status, rule read-back and state clear/kill use the nvlist ioctls (`DIOC*NV`); Enable/Disable and ListStates need a kernel with `COMPAT_FREEBSD14` (GENERIC has it), otherwise they return `pf.ErrNotSupported` |
| 15.0        | Expected to work, not tested |
| 14.5        | Tested in CI (struct ioctls, and the nvlist path forced) |
| 14.0 – 14.4 | Expected to work, not tested in CI |
| 13.x        | Untested, end of life |

The ioctl used for each operation is picked at compile time from what
`<net/pfvar.h>` defines, so build on the release you run on.
See `docs/compatibility.md` for detailed ioctl availability by version.

## Safety Warning

This library directly controls the operating system's firewall. Incorrect usage can lock you out of a remote system or expose it to unwanted traffic. In particular:

- Adding a "block all" rule without a preceding "pass" rule for your management connection will lock you out.
- Committing an empty ruleset will remove all existing rules.
- Disabling PF removes all packet filtering.

Test changes on a local or easily recoverable system before deploying to production. Use transactions to apply rulesets atomically -- if something goes wrong during rule addition, roll back.

## Building and Testing

`make help` lists all targets. The most common ones:

```
make build                       # build the package
make test                        # unit tests (any OS, no root)
make vet                         # go vet, including the integration tests
make examples                    # build the example programs
doas make test-integration       # integration tests (FreeBSD, root, pf.ko loaded)
doas make test-integration-pf    # ... including tests that enable PF (test VM only)
```

The integration tests (build tag `integration`) only touch the
`go-freebsd-pf-test` anchors and tap interfaces they create. Tests that need
PF enabled (state tests, Enable/Disable) are skipped unless
`GOPF_TEST_ENABLE_PF=1` is set, and even then they run only when PF is
disabled with an empty main ruleset: they load
`anchor "go-freebsd-pf-test/*"` plus `pass all no state`, enable PF, and
restore "disabled, no ruleset" afterwards. See
[CONTRIBUTING.md](CONTRIBUTING.md#safety-rules-for-pf-tests).

Examples are located in the `examples/` directory:

- `examples/status` -- Query and display PF status
- `examples/enable-disable` -- Enable and disable PF
- `examples/list-rules` -- List active filter rules
- `examples/add-block-rule` -- Add a block rule via transaction
- `examples/tables` -- Create and manage PF tables
- `examples/clear-states` -- Clear the state table
- `examples/transaction` -- Demonstrate atomic ruleset replacement

## Project Structure

```
pf/                  Public API and implementation
  client.go          Client type, Open/Close
  types.go           Go type definitions (Rule, Table, State, etc.)
  status.go          Enable, Disable, Status operations
  rules.go           Rule listing and management
  tables.go          Table and table address operations
  states.go          State listing and killing
  transaction.go     Atomic ruleset transactions
  anchors.go         Anchor listing
  convert.go         Go <-> C struct conversion
  cgo_freebsd.go     cgo bindings, per-release ioctl selection, nvlist code
  filter.go          State filtering helpers (portable)
  validate.go        Rule validation
  errors.go          Error types and mapping
  unsupported.go     Stub for non-FreeBSD builds
docs/                Design and technical documentation
examples/            Runnable example programs
internal/            Internal test utilities
```

## Documentation

- `docs/design.md` -- Architecture and design decisions
- `docs/pf-ioctl-notes.md` -- Technical notes on each PF ioctl used
- `docs/compatibility.md` -- FreeBSD version compatibility matrix
- [FEATURES.md](FEATURES.md) -- operations and the ioctl each uses per FreeBSD release
- [CHANGELOG.md](CHANGELOG.md) -- release notes

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security problems privately as
described in [SECURITY.md](SECURITY.md).

## License

BSD 2-Clause License. See LICENSE file.
