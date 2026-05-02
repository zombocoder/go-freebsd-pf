.PHONY: test test-integration lint examples freebsd-check vet

test:
	go test ./...

test-integration:
	sudo go test -tags=integration ./...

lint:
	golangci-lint run

examples:
	go build ./examples/...

freebsd-check:
	test "$$(uname -s)" = "FreeBSD"

vet:
	go vet ./...
