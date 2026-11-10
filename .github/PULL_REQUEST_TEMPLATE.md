## What and why

<!-- What does this change do, and what problem does it solve? Link issues with "Fixes #123". -->

## How it was tested

<!-- CI runs everything on FreeBSD 14.x and 15.x VMs. If you also tested locally, say how, e.g.:
     doas env GOPF_TEST_ENABLE_PF=1 go test -tags integration -p 1 ./... on FreeBSD 15.1 -->

## Checklist

- [ ] New behavior is covered by tests (a failing test first, then the fix)
- [ ] Integration tests use the `integration` build tag, need root, work only inside `go-freebsd-pf-test/...` anchors and on interfaces they create, and clean up with `defer`/`t.Cleanup`
- [ ] Tests that enable PF go through `enableSafePF` (gated by `GOPF_TEST_ENABLE_PF=1`, never touch a running firewall or a loaded ruleset)
- [ ] Where possible, tests check the result with `pfctl` rather than only with the library itself
- [ ] Version-dependent ioctls are selected in the C preamble from the `<net/pfvar.h>` macros, and `docs/compatibility.md` / `FEATURES.md` say which one each release uses
- [ ] cgo code frees every C allocation and passes no Go pointers inside structs handed to the kernel
- [ ] Public API changes are documented (doc comments, README, examples) and listed in `CHANGELOG.md`
- [ ] `gofmt -l .` prints nothing
