package pf

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestOpError(t *testing.T) {
	t.Run("with errno", func(t *testing.T) {
		e := &OpError{Op: "DIOCSTART", Errno: syscall.EPERM}
		got := e.Error()
		if !strings.Contains(got, "ioctl DIOCSTART failed") {
			t.Fatalf("unexpected error string: %s", got)
		}
		if !strings.HasPrefix(got, "pf: ") {
			t.Fatalf("error should start with 'pf: ', got: %s", got)
		}
	})

	t.Run("with wrapped error", func(t *testing.T) {
		inner := fmt.Errorf("something broke")
		e := &OpError{Op: "addRule", Err: inner}
		got := e.Error()
		if !strings.Contains(got, "addRule failed") {
			t.Fatalf("unexpected error string: %s", got)
		}
		if !strings.Contains(got, "something broke") {
			t.Fatalf("expected inner error message in output: %s", got)
		}
	})

	t.Run("format with errno zero and err set", func(t *testing.T) {
		e := &OpError{Op: "test", Err: ErrAlreadyEnabled}
		got := e.Error()
		// Errno == 0, so format is "pf: <op> failed: <err>"
		expected := "pf: test failed: pf: already enabled"
		if got != expected {
			t.Fatalf("expected %q, got %q", expected, got)
		}
	})
}

func TestOpErrorUnwrap(t *testing.T) {
	t.Run("unwraps inner error", func(t *testing.T) {
		e := &OpError{Op: "test", Err: ErrPermissionDenied}
		inner := e.Unwrap()
		if inner != ErrPermissionDenied {
			t.Fatalf("expected ErrPermissionDenied, got %v", inner)
		}
	})

	t.Run("unwraps errno when no Err", func(t *testing.T) {
		e := &OpError{Op: "test", Errno: syscall.EINVAL}
		inner := e.Unwrap()
		if inner != syscall.EINVAL {
			t.Fatalf("expected syscall.EINVAL, got %v", inner)
		}
	})
}

func TestMapErrno(t *testing.T) {
	tests := []struct {
		name     string
		errno    syscall.Errno
		sentinel error
	}{
		{"EEXIST maps to AlreadyEnabled", syscall.EEXIST, ErrAlreadyEnabled},
		{"ENOENT maps to AlreadyDisabled", syscall.ENOENT, ErrAlreadyDisabled},
		{"EPERM maps to PermissionDenied", syscall.EPERM, ErrPermissionDenied},
		{"EACCES maps to PermissionDenied", syscall.EACCES, ErrPermissionDenied},
		{"ENODEV maps to DeviceNotFound", syscall.ENODEV, ErrDeviceNotFound},
		{"EINVAL maps to InvalidArgument", syscall.EINVAL, ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := mapErrno("testOp", tc.errno)
			if err == nil {
				t.Fatal("expected non-nil error")
			}

			var opErr *OpError
			if !errors.As(err, &opErr) {
				t.Fatalf("expected *OpError, got %T", err)
			}

			if opErr.Op != "testOp" {
				t.Fatalf("expected Op 'testOp', got %q", opErr.Op)
			}

			if opErr.Errno != tc.errno {
				t.Fatalf("expected Errno %v, got %v", tc.errno, opErr.Errno)
			}

			if opErr.Err != tc.sentinel {
				t.Fatalf("expected Err %v, got %v", tc.sentinel, opErr.Err)
			}
		})
	}

	t.Run("unknown errno has nil Err", func(t *testing.T) {
		err := mapErrno("testOp", syscall.ENOSYS)
		var opErr *OpError
		if !errors.As(err, &opErr) {
			t.Fatalf("expected *OpError, got %T", err)
		}
		if opErr.Err != nil {
			t.Fatalf("expected nil Err for unknown errno, got %v", opErr.Err)
		}
		if opErr.Errno != syscall.ENOSYS {
			t.Fatalf("expected ENOSYS, got %v", opErr.Errno)
		}
	})
}

func TestCompatUnsupported(t *testing.T) {
	t.Run("ENODEV becomes ErrNotSupported", func(t *testing.T) {
		err := compatUnsupported(mapErrno("DIOCGETSTATESV2", syscall.ENODEV))
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("expected ErrNotSupported, got %v", err)
		}
		var opErr *OpError
		if !errors.As(err, &opErr) {
			t.Fatalf("expected *OpError, got %T", err)
		}
		if opErr.Op != "DIOCGETSTATESV2" || opErr.Errno != syscall.ENODEV {
			t.Fatalf("op/errno not preserved: %+v", opErr)
		}
	})

	t.Run("ENOTTY becomes ErrNotSupported", func(t *testing.T) {
		err := compatUnsupported(mapErrno("DIOCSTART", syscall.ENOTTY))
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("expected ErrNotSupported, got %v", err)
		}
	})

	t.Run("other errors pass through", func(t *testing.T) {
		in := mapErrno("DIOCSTART", syscall.EEXIST)
		if got := compatUnsupported(in); got != in {
			t.Fatalf("expected error unchanged, got %v", got)
		}
		if got := compatUnsupported(nil); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}

func TestIsErrno(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", mapErrno("DIOCGETRULES", syscall.EINVAL))
	if !isErrno(err, syscall.EINVAL) {
		t.Fatal("expected EINVAL to be found through the sentinel mapping")
	}
	if isErrno(err, syscall.ENOENT) {
		t.Fatal("unexpected ENOENT match")
	}
	if isErrno(fmt.Errorf("plain"), syscall.EINVAL) {
		t.Fatal("plain error must not match")
	}
}
