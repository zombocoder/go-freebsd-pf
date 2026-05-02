package pf

import (
	"errors"
	"fmt"
	"syscall"
)

var (
	// ErrUnsupportedPlatform is returned on non-FreeBSD systems.
	ErrUnsupportedPlatform = errors.New("pf: unsupported platform")

	// ErrPermissionDenied is returned when the caller lacks privileges.
	ErrPermissionDenied = errors.New("pf: permission denied")

	// ErrDeviceNotFound is returned when /dev/pf is not available.
	ErrDeviceNotFound = errors.New("pf: /dev/pf not found")

	// ErrAlreadyEnabled is returned when PF is already enabled.
	ErrAlreadyEnabled = errors.New("pf: already enabled")

	// ErrAlreadyDisabled is returned when PF is already disabled.
	ErrAlreadyDisabled = errors.New("pf: already disabled")

	// ErrInvalidRule is returned when a rule fails validation.
	ErrInvalidRule = errors.New("pf: invalid rule")

	// ErrTransactionClosed is returned when operating on a finished transaction.
	ErrTransactionClosed = errors.New("pf: transaction already closed")

	// ErrInvalidArgument is returned when an argument is malformed.
	ErrInvalidArgument = errors.New("pf: invalid argument")

	// ErrTableNotFound is returned when a referenced table does not exist.
	ErrTableNotFound = errors.New("pf: table not found")

	// ErrNoStates is returned when no states match a filter.
	ErrNoStates = errors.New("pf: no matching states")
)

// OpError describes a failed PF ioctl operation.
type OpError struct {
	Op    string
	Errno syscall.Errno
	Err   error
}

func (e *OpError) Error() string {
	if e.Errno != 0 {
		return fmt.Sprintf("pf: ioctl %s failed: %v", e.Op, e.Errno)
	}
	return fmt.Sprintf("pf: %s failed: %v", e.Op, e.Err)
}

func (e *OpError) Unwrap() error {
	if e.Err != nil {
		return e.Err
	}
	return e.Errno
}

// mapErrno converts common errno values to package-level sentinel errors.
func mapErrno(op string, errno syscall.Errno) error {
	switch errno {
	case syscall.EEXIST:
		return &OpError{Op: op, Errno: errno, Err: ErrAlreadyEnabled}
	case syscall.ENOENT:
		return &OpError{Op: op, Errno: errno, Err: ErrAlreadyDisabled}
	case syscall.EPERM, syscall.EACCES:
		return &OpError{Op: op, Errno: errno, Err: ErrPermissionDenied}
	case syscall.ENODEV:
		return &OpError{Op: op, Errno: errno, Err: ErrDeviceNotFound}
	case syscall.EINVAL:
		return &OpError{Op: op, Errno: errno, Err: ErrInvalidArgument}
	default:
		return &OpError{Op: op, Errno: errno}
	}
}
