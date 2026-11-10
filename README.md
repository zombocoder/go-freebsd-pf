# go-freebsd-pf

[![Go Reference](https://pkg.go.dev/badge/github.com/zombocoder/go-freebsd-pf.svg)](https://pkg.go.dev/github.com/zombocoder/go-freebsd-pf)
[![FreeBSD](https://img.shields.io/badge/platform-FreeBSD-red.svg)](https://www.freebsd.org/)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-green.svg)](LICENSE)

A Go library for managing the FreeBSD PF (Packet Filter) firewall via /dev/pf ioctls.

This library provides a native Go interface to PF's kernel-level ioctl API, enabling programmatic control of firewall rules, tables, state tracking, and configuration from Go applications.

**This library only works on FreeBSD.** It requires cgo and root privileges.

## Requirements

- FreeBSD 13.2 or later (13.x, 14.x, 15.x)
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
| 13.2 – 13.5 | Supported |
| 14.0 – 14.3 | Supported |
| 15.0 – 15.1 | Supported. Status, rule read-back and state clear/kill use the nvlist ioctls (`DIOC*NV`); Enable/Disable and ListStates need a kernel with `COMPAT_FREEBSD14` (GENERIC has it), otherwise they return `pf.ErrNotSupported` |

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

Verify you are on FreeBSD:

```
make freebsd-check
```

Run the linter and vet:

```
make lint
make vet
```

Run unit tests:

```
make test
```

Run integration tests (requires root and a loaded `pf.ko`):

```
make test-integration
```

The integration tests only touch the `go-freebsd-pf-test` anchors and tap
interfaces they create. Tests that need PF enabled (state tests,
Enable/Disable) are skipped unless `GOPF_TEST_ENABLE_PF=1` is set, and even
then they run only when PF is disabled with an empty main ruleset: they load
`anchor "go-freebsd-pf-test/*"` plus `pass all no state`, enable PF, and
restore "disabled, no ruleset" afterwards.

```
doas env GOPF_TEST_ENABLE_PF=1 go test -tags integration ./pf/
```

Build all examples:

```
make examples
```

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
  convert.go         Go <-> C struct conversion
  cgo_freebsd.go     cgo bindings and C helper functions
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

## License

BSD 2-Clause License. See LICENSE file.
