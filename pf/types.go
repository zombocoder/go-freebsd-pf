package pf

import (
	"net"
	"time"
)

// Action represents a PF rule action.
type Action uint8

const (
	ActionPass  Action = iota // pass
	ActionBlock               // block
	ActionMatch               // match
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionBlock:
		return "block"
	case ActionMatch:
		return "match"
	default:
		return "unknown"
	}
}

// Direction represents a PF rule direction.
type Direction uint8

const (
	DirectionAny Direction = iota // in/out
	DirectionIn                   // in
	DirectionOut                  // out
)

func (d Direction) String() string {
	switch d {
	case DirectionIn:
		return "in"
	case DirectionOut:
		return "out"
	case DirectionAny:
		return ""
	default:
		return "unknown"
	}
}

// Protocol represents a network protocol.
type Protocol uint8

const (
	ProtocolAny  Protocol = 0
	ProtocolICMP Protocol = 1
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
)

func (p Protocol) String() string {
	switch p {
	case ProtocolAny:
		return ""
	case ProtocolICMP:
		return "icmp"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// PortOperator represents a port comparison operator.
type PortOperator uint8

const (
	PortOpNone  PortOperator = iota // no port match
	PortOpIRG                       // inclusive range
	PortOpEq                        // =
	PortOpNe                        // !=
	PortOpLt                        // <
	PortOpLe                        // <=
	PortOpGt                        // >
	PortOpGe                        // >=
	PortOpXRG                       // exclusive range
	PortOpRRG                       // reverse range
)

// PortMatcher matches a port or port range.
type PortMatcher struct {
	Operator PortOperator
	From     uint16
	To       uint16
}

// IsAny returns true if this matcher matches any port.
func (pm PortMatcher) IsAny() bool {
	return pm.Operator == PortOpNone
}

// AddressType represents the type of address match.
type AddressType uint8

const (
	AddressTypeMask    AddressType = iota // address/mask
	AddressTypeNoRoute                    // no-route
	AddressTypeDynIf                      // dynamic interface
	AddressTypeTable                      // table reference
	AddressTypeURPF                       // urpf-failed
	AddressTypeRange                      // range
)

// Address represents a PF address match.
type Address struct {
	IP      net.IP
	Network *net.IPNet
	Any     bool
	Table   string // e.g. "blocked_hosts" (without angle brackets)
	Negate  bool
}

// Rule represents a PF firewall rule.
type Rule struct {
	Action    Action
	Direction Direction
	Interface string
	Protocol  Protocol
	AF        AddressFamily

	Source      Address
	Destination Address

	SourcePort      PortMatcher
	DestinationPort PortMatcher

	Quick     bool
	Log       bool
	KeepState bool
	Label     string
	Anchor    string

	Nr uint32 // rule number (read-only, set by kernel)
}

// AddressFamily represents the address family.
type AddressFamily uint8

const (
	AddressFamilyAny  AddressFamily = 0
	AddressFamilyIPv4 AddressFamily = 2  // AF_INET
	AddressFamilyIPv6 AddressFamily = 28 // AF_INET6 on FreeBSD
)

// RuleSet identifies which set of rules to operate on.
type RuleSet int

const (
	RuleSetScrub  RuleSet = 0
	RuleSetFilter RuleSet = 1
	RuleSetNAT    RuleSet = 2
	RuleSetBINAT  RuleSet = 3
	RuleSetRDR    RuleSet = 4
)

// RuleQuery specifies which rules to retrieve.
type RuleQuery struct {
	Anchor  string
	RuleSet RuleSet
}

// DebugLevel represents PF debug level.
type DebugLevel uint32

const (
	DebugNone   DebugLevel = 0
	DebugUrgent DebugLevel = 1
	DebugMisc   DebugLevel = 2
	DebugNoisy  DebugLevel = 3
)

func (d DebugLevel) String() string {
	switch d {
	case DebugNone:
		return "none"
	case DebugUrgent:
		return "urgent"
	case DebugMisc:
		return "misc"
	case DebugNoisy:
		return "noisy"
	default:
		return "unknown"
	}
}

// Status holds PF status information.
type Status struct {
	Running    bool
	Since      time.Time
	Debug      DebugLevel
	HostID     uint32
	Interface  string
	States     uint32
	SrcNodes   uint32
	Counters   StatusCounters
	Checksum   [16]byte
}

// StatusCounters holds various PF counters.
type StatusCounters struct {
	Counters  []uint64
	LCounters []uint64
	FCounters []uint64
	SCounters []uint64
}

// TableFlags represents PF table flags.
type TableFlags uint32

const (
	TableFlagPersist TableFlags = 0x01
	TableFlagConst   TableFlags = 0x02
	TableFlagActive  TableFlags = 0x04
	TableFlagInactive TableFlags = 0x08
	TableFlagReferenced TableFlags = 0x10
	TableFlagRefdAnch TableFlags = 0x20
	TableFlagCounters TableFlags = 0x40
)

// Table represents a PF table.
type Table struct {
	Name   string
	Anchor string
	Flags  TableFlags
}

// TableAddress represents an address in a PF table.
type TableAddress struct {
	IP      net.IP
	Network *net.IPNet
	Negate  bool
}

// State represents a PF state table entry.
type State struct {
	ID          uint64
	CreatorID   uint32
	Interface   string
	Protocol    Protocol
	Direction   Direction
	AF          AddressFamily
	Source      net.IP
	Destination net.IP
	SourcePort  uint16
	DestPort    uint16
	Packets     [2]uint64
	Bytes       [2]uint64
	Creation    time.Duration
	Expire      time.Duration
}

// StateFilter specifies criteria for filtering states.
type StateFilter struct {
	Interface   string
	Source      *net.IPNet
	Destination *net.IPNet
	Label       string
}
