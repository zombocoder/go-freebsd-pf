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

	// ProtocolICMPv6 is IPPROTO_ICMPV6.
	ProtocolICMPv6 Protocol = 58
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
	case ProtocolICMPv6:
		return "ipv6-icmp" // getprotobynumber(58), as pfctl prints it
	default:
		return "unknown"
	}
}

// PortOperator represents a port comparison operator.
type PortOperator uint8

const (
	PortOpNone PortOperator = iota // no port match
	PortOpIRG                      // inclusive range
	PortOpEq                       // =
	PortOpNe                       // !=
	PortOpLt                       // <
	PortOpLe                       // <=
	PortOpGt                       // >
	PortOpGe                       // >=
	PortOpXRG                      // exclusive range
	PortOpRRG                      // reverse range
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

	// Interface makes this a dynamic interface address, pfctl's "(self)" or
	// "(vtnet0)": the addresses currently on that interface or group,
	// tracked by the kernel. It excludes Any, IP, Network and Table; a /N prefix on a dynamic
	// address is not supported.
	// IfaceFlags refines it ("(vtnet0:network)"). A dynamic address does not
	// fix the rule's address family; set Rule.AF to restrict it.
	Interface  string
	IfaceFlags IfaceFlags
}

// IfaceFlags are the modifiers of a dynamic interface address, from
// PFI_AFLAG_*. At most one of IfaceNetwork, IfaceBroadcast and IfacePeer.
type IfaceFlags uint8

const (
	IfaceNetwork   IfaceFlags = 0x01 // (if:network)
	IfaceBroadcast IfaceFlags = 0x02 // (if:broadcast)
	IfacePeer      IfaceFlags = 0x04 // (if:peer)
	IfaceNoAlias   IfaceFlags = 0x08 // (if:0): no alias addresses
)

// TCP header flag bits for TCPFlags.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
	TCPFlagECE uint8 = 0x40
	TCPFlagCWR uint8 = 0x80
)

// TCPFlags is pfctl's "flags Check/Mask": the packet matches when
// (flags & Mask) == Check. The zero value matches any flags.
type TCPFlags struct {
	Check uint8
	Mask  uint8
}

// FlagsSA returns "flags S/SA", the usual first-packet-of-a-connection test.
func FlagsSA() TCPFlags { return TCPFlags{Check: TCPFlagSYN, Mask: TCPFlagSYN | TCPFlagACK} }

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
	KeepState bool // keep state; does not add `flags S/SA` (see TCPFlags)
	Label     string
	Anchor    string

	// TCPFlags is "flags Check/Mask"; only with ProtocolTCP. KeepState does
	// not imply pfctl's default `flags S/SA`: a TCP pass rule without
	// TCPFlags matches any flags, so set TCPFlags: FlagsSA() where pfctl
	// would have defaulted it. Stricter than pfctl, which silently drops
	// flags on non-TCP rules: they are rejected here.
	TCPFlags TCPFlags

	// ICMPType and ICMPCode match the ICMP/ICMPv6 type and code (pfctl's
	// icmp-type N code M; the numeric values, not names). ICMPCode needs
	// ICMPType; both need ProtocolICMP or ProtocolICMPv6 (stricter than
	// pfctl, which ignores them elsewhere). nil matches any. ProtocolICMP
	// implies inet and ProtocolICMPv6 inet6 when AF is unset; the other
	// family is rejected.
	ICMPType *uint8
	ICMPCode *uint8

	// AnchorCall is set by ListRules on a rule that evaluates an anchor
	// (pfctl's `anchor "name"`), to the anchor path as the kernel reports it,
	// including a trailing "/*" for a wildcard. Read-only: AddRule ignores it.
	AnchorCall string

	// BlockPolicy is the policy of a block rule (drop, return, return-rst,
	// return-icmp). The zero value is BlockPolicyDrop; any other value is
	// rejected for pass and match rules, and BlockPolicyReturnRST needs
	// ProtocolTCP. The kernel keeps custom return-icmp codes and a return-rst
	// TTL; this package writes pfctl's defaults and ListRules reads back only
	// the bare policy, so those details are lost on a round trip.
	BlockPolicy BlockPolicy

	// Rtable is the routing table (FIB) the rule selects, as pfctl's
	// `rtable N`. nil means the rule has no rtable option (rtableid -1 in
	// the kernel); a pointer to 0 means `rtable 0` explicitly. ListRules
	// reports nil for rules without rtable. A value above 0 must be below the
	// kernel's net.fibs, or the kernel rejects the rule.
	Rtable *int

	Nr uint32 // rule number (read-only, set by kernel)

	// Per-rule statistics (read-only, populated by ListRules).
	Evaluations uint64
	Packets     [2]uint64 // [in, out]
	Bytes       [2]uint64 // [in, out]
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

// Status holds PF status information, equivalent to `pfctl -s info`.
type Status struct {
	Running    bool
	Since      time.Time
	Debug      DebugLevel
	HostID     uint32
	Interface  string
	States     uint32
	SrcNodes   uint32
	Counters   StatusCounters
	StateTable StateTableCounters
	Checksum   [16]byte
}

// StatusCounters holds PF packet match counters (the "Counters" section
// of `pfctl -s info`).
type StatusCounters struct {
	Match         uint64
	BadOffset     uint64
	Fragment      uint64
	Short         uint64
	Normalize     uint64
	Memory        uint64
	BadTimestamp  uint64
	Congestion    uint64
	IPOption      uint64
	ProtoChecksum uint64
	StateMismatch uint64
	StateInsert   uint64
	StateLimit    uint64
	SrcLimit      uint64
	SynProxy      uint64
	MapFailed     uint64
}

// StateTableCounters holds state table search/insert/removal counters
// (the "State Table" section of `pfctl -s info`).
type StateTableCounters struct {
	Searches uint64
	Inserts  uint64
	Removals uint64
}

// LimitCounters holds limit-related counters.
type LimitCounters struct {
	States        uint64
	SrcStates     uint64
	SrcNodes      uint64
	SrcConn       uint64
	SrcConnRate   uint64
	OverloadTable uint64
	OverloadFlush uint64
}

// TableFlags represents PF table flags.
type TableFlags uint32

const (
	TableFlagPersist    TableFlags = 0x01
	TableFlagConst      TableFlags = 0x02
	TableFlagActive     TableFlags = 0x04
	TableFlagInactive   TableFlags = 0x08
	TableFlagReferenced TableFlags = 0x10
	TableFlagRefdAnch   TableFlags = 0x20
	TableFlagCounters   TableFlags = 0x40
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
	ID        uint64
	CreatorID uint32
	// Interface is the interface the state is bound to: "all" for a
	// floating state (the default state-policy), else an interface name.
	Interface string
	// OrigInterface is the interface the state was created on.
	OrigInterface string
	Protocol      Protocol
	Direction     Direction
	AF            AddressFamily
	Source        net.IP
	Destination   net.IP
	SourcePort    uint16
	DestPort      uint16
	Packets       [2]uint64
	Bytes         [2]uint64
	Creation      time.Duration
	Expire        time.Duration
}

// StateFilter specifies criteria for filtering states.
type StateFilter struct {
	// Interface selects states as the kernel does for kill/clear: a
	// floating state by the interface it was created on (OrigInterface),
	// an if-bound state by the interface it is bound to. "all" therefore
	// matches no floating state; use an empty Interface for every state.
	Interface   string
	Source      *net.IPNet
	Destination *net.IPNet
	Label       string
}
