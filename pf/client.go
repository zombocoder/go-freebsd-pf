//go:build freebsd && cgo

package pf

import (
	"fmt"
	"os"
	"sync"
)

const defaultDevice = "/dev/pf"

// Options configures the PF client.
type Options struct {
	Device string // default: /dev/pf
}

// Client provides access to the FreeBSD PF firewall via /dev/pf.
// A Client must not be used concurrently from multiple goroutines
// without external synchronization.
type Client struct {
	mu     sync.Mutex
	fd     int
	file   *os.File
	closed bool
}

// Open opens the PF device with the given options.
func Open(opts Options) (*Client, error) {
	device := opts.Device
	if device == "" {
		device = defaultDevice
	}

	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %v", ErrDeviceNotFound, err)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return nil, fmt.Errorf("pf: open %s: %w", device, err)
	}

	return &Client{
		fd:   int(f.Fd()),
		file: f,
	}, nil
}

// OpenDefault opens /dev/pf with default options.
func OpenDefault() (*Client, error) {
	return Open(Options{})
}

// Close closes the PF device.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	return c.file.Close()
}

// FD returns the underlying file descriptor.
func (c *Client) FD() uintptr {
	return uintptr(c.fd)
}

func (c *Client) checkClosed() error {
	if c.closed {
		return fmt.Errorf("pf: client is closed")
	}
	return nil
}
