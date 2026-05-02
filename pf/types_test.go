package pf

import "testing"

func TestActionString(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{ActionPass, "pass"},
		{ActionBlock, "block"},
		{ActionMatch, "match"},
		{Action(255), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.action.String(); got != tc.want {
				t.Fatalf("Action(%d).String() = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

func TestDirectionString(t *testing.T) {
	tests := []struct {
		dir  Direction
		want string
	}{
		{DirectionAny, ""},
		{DirectionIn, "in"},
		{DirectionOut, "out"},
		{Direction(99), "unknown"},
	}
	for _, tc := range tests {
		name := tc.want
		if name == "" {
			name = "any_empty"
		}
		t.Run(name, func(t *testing.T) {
			if got := tc.dir.String(); got != tc.want {
				t.Fatalf("Direction(%d).String() = %q, want %q", tc.dir, got, tc.want)
			}
		})
	}
}

func TestProtocolString(t *testing.T) {
	tests := []struct {
		proto Protocol
		want  string
	}{
		{ProtocolAny, ""},
		{ProtocolICMP, "icmp"},
		{ProtocolTCP, "tcp"},
		{ProtocolUDP, "udp"},
		{Protocol(200), "unknown"},
	}
	for _, tc := range tests {
		name := tc.want
		if name == "" {
			name = "any_empty"
		}
		t.Run(name, func(t *testing.T) {
			if got := tc.proto.String(); got != tc.want {
				t.Fatalf("Protocol(%d).String() = %q, want %q", tc.proto, got, tc.want)
			}
		})
	}
}

func TestDebugLevelString(t *testing.T) {
	tests := []struct {
		level DebugLevel
		want  string
	}{
		{DebugNone, "none"},
		{DebugUrgent, "urgent"},
		{DebugMisc, "misc"},
		{DebugNoisy, "noisy"},
		{DebugLevel(100), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.level.String(); got != tc.want {
				t.Fatalf("DebugLevel(%d).String() = %q, want %q", tc.level, got, tc.want)
			}
		})
	}
}

func TestPortMatcherIsAny(t *testing.T) {
	t.Run("PortOpNone is any", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpNone}
		if !pm.IsAny() {
			t.Fatal("expected IsAny() == true for PortOpNone")
		}
	})

	t.Run("PortOpEq is not any", func(t *testing.T) {
		pm := PortMatcher{Operator: PortOpEq, From: 80}
		if pm.IsAny() {
			t.Fatal("expected IsAny() == false for PortOpEq")
		}
	})

	t.Run("zero value is any", func(t *testing.T) {
		pm := PortMatcher{}
		if !pm.IsAny() {
			t.Fatal("expected IsAny() == true for zero-value PortMatcher")
		}
	})
}
