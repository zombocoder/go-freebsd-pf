.PHONY: all build test test-unit test-integration test-integration-pf test-coverage clean examples install fmt fmt-check vet lint check tidy freebsd-check list-examples version help docs

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Build parameters
BUILD_FLAGS=-v
TEST_FLAGS=-v

# Example programs (one directory per program). The Makefile works with
# both FreeBSD's make and GNU make, so no GNU-only functions.
EXAMPLES=examples/add-block-rule examples/clear-states examples/enable-disable examples/list-rules examples/status examples/tables examples/transaction
EXAMPLE_BINS=$(EXAMPLES:=/main)


all: check build

##@ Build

build: ## Build all packages
	@echo "Building packages..."
	@$(GOBUILD) $(BUILD_FLAGS) ./...

examples: ## Build all example programs
	@for d in $(EXAMPLES); do \
		echo "Building $$d/main..."; \
		$(GOBUILD) $(BUILD_FLAGS) -o $$d/main ./$$d || exit 1; \
	done

install: ## Install the library
	@echo "Installing packages..."
	@$(GOCMD) install ./...

##@ Testing

test: test-unit ## Run all tests that need no root (alias for test-unit)

test-unit: ## Run unit tests (no root; also runs on non-FreeBSD hosts)
	@echo "Running unit tests..."
	@$(GOTEST) $(TEST_FLAGS) ./...

test-integration: freebsd-check ## Run integration tests (root; PF-enabling tests skip)
	@echo "Running integration tests (requires root and pf.ko)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: Integration tests require root privileges"; \
		echo "Run: doas make test-integration"; \
		exit 1; \
	fi
	@$(GOTEST) -tags integration -count=1 -p 1 $(TEST_FLAGS) ./...

test-integration-pf: freebsd-check ## Integration tests incl. enabling PF (root; test VM only)
	@echo "Running integration tests with GOPF_TEST_ENABLE_PF=1."
	@echo "They enable PF with a pass-all ruleset if PF is disabled with an empty"
	@echo "main ruleset, and restore that state afterwards. Use a VM or test host."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: Integration tests require root privileges"; \
		echo "Run: doas make test-integration-pf"; \
		exit 1; \
	fi
	@GOPF_TEST_ENABLE_PF=1 $(GOTEST) -tags integration -count=1 -p 1 $(TEST_FLAGS) ./...

test-coverage: ## Generate unit test coverage report
	@echo "Generating coverage report..."
	@$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./...
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

##@ Code Quality

fmt: ## Format all Go source files
	@echo "Formatting code..."
	@$(GOFMT) -w .

fmt-check: ## Fail if any file is not gofmt-formatted (as CI does)
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi

vet: ## Run go vet (including the integration tests)
	@echo "Running go vet..."
	@$(GOVET) ./...
	@$(GOVET) -tags integration ./...

check: fmt vet ## Run fmt and vet

lint: ## Run static analysis (requires staticcheck)
	@echo "Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not found. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

##@ Documentation

docs: ## View package documentation (using go doc)
	@$(GOCMD) doc -all ./pf

##@ Maintenance

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -f $(EXAMPLE_BINS) coverage.out coverage.html
	@echo "Clean complete"

tidy: ## Tidy go.mod
	@echo "Tidying go.mod..."
	@$(GOCMD) mod tidy

freebsd-check: ## Fail unless running on FreeBSD
	@test "$$(uname -s)" = "FreeBSD" || { echo "Error: requires FreeBSD"; exit 1; }

##@ Information

list-examples: ## List all example programs
	@echo "Available examples (all need root and /dev/pf):"
	@echo "  examples/status          - Show PF status and counters"
	@echo "  examples/enable-disable  - Enable and disable PF"
	@echo "  examples/list-rules      - List rules of the main ruleset or an anchor"
	@echo "  examples/add-block-rule  - Add a block rule via a transaction"
	@echo "  examples/transaction     - Atomic ruleset replacement"
	@echo "  examples/tables          - Create and manage PF tables"
	@echo "  examples/clear-states    - Clear the state table"
	@echo ""
	@echo "To run an example:"
	@echo "  doas go run ./examples/status"

version: ## Show Go version and module info
	@echo "Go version:"
	@$(GOCMD) version
	@echo ""
	@echo "Module info:"
	@$(GOCMD) list -m

##@ Help

help: ## Display this help message
	@echo "================================================================================"
	@echo " go-freebsd-pf - FreeBSD PF (Packet Filter) library for Go"
	@echo "================================================================================"
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ { printf "\n%s\n", substr($$0, 5) } \
		/^[a-zA-Z0-9_-]+:.*## / { printf "  %-22s %s\n", $$1, $$2 }' Makefile
	@echo ""
	@echo "================================================================================"
	@echo "Quick Start:"
	@echo "  make build                    # Build all packages"
	@echo "  make test                     # Unit tests"
	@echo "  doas make test-integration    # Integration tests (root)"
	@echo ""
	@echo "Documentation:"
	@echo "  https://pkg.go.dev/github.com/zombocoder/go-freebsd-pf"
	@echo "================================================================================"
