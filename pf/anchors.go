//go:build freebsd && cgo

package pf

/*
#cgo freebsd CFLAGS: -D__BSD_VISIBLE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <string.h>

static int pf_ioctl_getrulesets(int fd, struct pfioc_ruleset *rs) {
	return ioctl(fd, DIOCGETRULESETS, rs);
}

static int pf_ioctl_getruleset(int fd, struct pfioc_ruleset *rs) {
	return ioctl(fd, DIOCGETRULESET, rs);
}
*/
import "C"
import (
	"strings"
	"unsafe"
)

// Anchor represents a PF anchor.
type Anchor struct {
	Name string
	Path string
}

// ListAnchors returns all anchors under the given path (empty for root).
func (c *Client) ListAnchors(path string) ([]Anchor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClosed(); err != nil {
		return nil, err
	}

	var rs C.struct_pfioc_ruleset
	C.memset(unsafe.Pointer(&rs), 0, C.sizeof_struct_pfioc_ruleset)

	if err := copyStringToC(&rs.path[0], "anchor", path, C.MAXPATHLEN); err != nil {
		return nil, err
	}

	// Get count of anchors
	rv, err := C.pf_ioctl_getrulesets(C.int(c.fd), &rs)
	if ioctlErr("DIOCGETRULESETS", rv, err) != nil {
		return nil, ioctlErr("DIOCGETRULESETS", rv, err)
	}

	count := uint32(rs.nr)
	anchors := make([]Anchor, 0, count)

	for i := uint32(0); i < count; i++ {
		var grs C.struct_pfioc_ruleset
		C.memset(unsafe.Pointer(&grs), 0, C.sizeof_struct_pfioc_ruleset)
		_ = copyStringToC(&grs.path[0], "anchor", path, C.MAXPATHLEN) // fits, checked above
		grs.nr = C.u_int32_t(i)

		rv, err := C.pf_ioctl_getruleset(C.int(c.fd), &grs)
		if ioctlErr("DIOCGETRULESET", rv, err) != nil {
			return anchors, ioctlErr("DIOCGETRULESET", rv, err)
		}

		name := strings.TrimRight(C.GoString(&grs.name[0]), "\x00")
		p := strings.TrimRight(C.GoString(&grs.path[0]), "\x00")
		anchors = append(anchors, Anchor{
			Name: name,
			Path: p,
		})
	}

	return anchors, nil
}
