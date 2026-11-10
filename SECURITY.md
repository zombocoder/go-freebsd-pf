# Security Policy

## Supported versions

Security fixes are made on the `main` branch and released as a new patch or
minor version of the latest release (currently 0.x).

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub:
[Report a vulnerability](https://github.com/zombocoder/go-freebsd-pf/security/advisories/new)
(Security tab → "Report a vulnerability").

Include what you can of:

- the affected function and the commit you tested;
- the FreeBSD version (`freebsd-version -ku`), architecture and kernel
  configuration (GENERIC or custom);
- steps or a minimal program that reproduces the problem;
- the impact you expect (memory corruption, a rule loaded into the wrong
  anchor or ruleset, states killed that should not have been, traffic passed
  that should have been blocked, ...).

You should get a first response within a week. Once a fix is available, the
advisory is published with credit to the reporter unless you prefer otherwise.

## Scope

This library controls the host firewall through `/dev/pf` ioctls via cgo and
is typically used by privileged processes. Of particular interest are:

- memory-safety bugs in the cgo layer (`pf/cgo_freebsd.go` and the C
  preambles), such as out-of-bounds reads or writes of kernel request
  structures, wrong struct layouts, nvlist encoding/decoding errors, leaks,
  or Go pointers handed to the kernel;
- operations that act on a different anchor, ruleset, table or set of states
  than requested, or that load a rule different from the one passed in
  (for example a dropped `quick`, address or port);
- input that reaches an ioctl without the validation callers would expect
  (anchor, table and interface names, labels, addresses).

Bugs in PF or the FreeBSD kernel itself should be reported to the
[FreeBSD security team](https://www.freebsd.org/security/).
