# gibson-executor — one microVM image, one Go binary, N parsers.
#
# Targets:
#   make build      Org-contract alias for bin (gibson#171 slice 1.4)
#   make bin        Build the runner binary to ./bin/gibson-runner
#   make test       Run unit tests (parsers, registry)
#   make check      CI-equivalent gate: test only (org contract) — lint runs
#                   natively in CI (go-ci.yml) and is deliberately excluded
#                   here; see the note above `check` below.
#   make list-tools Build the binary and print its catalog
#   make lint       Repo-pinned golangci-lint (blocking; new since LINT_BASE)
#   make image      Build the OCI image for local smoke via Setec
#   make clean      Remove ./bin and ./out

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eo pipefail -c

BIN_DIR := bin
IMAGE   ?= ghcr.io/zeroroot-ai/gibson-executor:dev

.PHONY: help
help: ## List targets.
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# build: org Makefile contract target (gibson#171 slice 1.4 /
# zeroroot-ai/.github#87). Aliases bin so CI and the drift-detector
# find a canonical build target.
.PHONY: build
build: bin ## Build the runner binary (org-contract alias for bin).

.PHONY: bin
bin: ## Build ./bin/gibson-runner (CGO disabled, static).
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/gibson-runner ./cmd/gibson-runner

.PHONY: test
test: ## Run unit tests with the race detector.
	go test -race ./...

.PHONY: test-coverage
test-coverage: ## Produce a coverage report.
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: list-tools
list-tools: bin ## Build the binary and print its parser catalog as JSON.
	./$(BIN_DIR)/gibson-runner --list-tools

# golangci-lint version — pinned for reproducible lint output (#131). v2
# schema (.golangci.yml `version: "2"`). Built from source with the repo's
# own Go toolchain (GOLANGCI_BUILD_TOOLCHAIN below) so its embedded Go
# version is never lower than go.mod's `go` target — golangci v2 refuses to
# load a newer target otherwise, the "v2 trap" that bit sdk#355 / adk#154 /
# gibson#1234.
GOLANGCI_LINT_VERSION := v2.8.0

# Toolchain used to BUILD golangci-lint, derived from go.mod's `go`
# directive so it can never drift when go.mod bumps. golangci's own go.mod
# declares an older `go` directive, so with GOTOOLCHAIN=auto Go would build
# it with that older compiler instead — hence the explicit override below.
GOLANGCI_BUILD_TOOLCHAIN := go$(shell awk '$$1 == "go" {print $$2; exit}' go.mod)

# golangci-lint binary, pinned + repo-local (under bin/tools/, gitignored).
# make ALWAYS invokes this path — a system golangci-lint from PATH is never
# used, so a stale system binary cannot poison `make lint`.
GOLANGCI_LINT := bin/tools/golangci-lint

# Stamp recording which version+toolchain the installed binary was built
# with. When either pin moves (go.mod bump, GOLANGCI_LINT_VERSION bump), the
# stamp mismatch deletes the stale binary and triggers a rebuild instead of
# golangci surfacing its opaque version-refusal error at `run` time.
GOLANGCI_LINT_STAMP := bin/tools/.golangci-lint-$(GOLANGCI_LINT_VERSION)-$(GOLANGCI_BUILD_TOOLCHAIN).stamp

$(GOLANGCI_LINT_STAMP):
	@mkdir -p bin/tools
	@rm -f bin/tools/.golangci-lint-*.stamp $(GOLANGCI_LINT)
	@touch $@

$(GOLANGCI_LINT): $(GOLANGCI_LINT_STAMP)
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) to $(CURDIR)/bin/tools (toolchain $(GOLANGCI_BUILD_TOOLCHAIN))..."
	@mkdir -p bin/tools
	@GOTOOLCHAIN=$(GOLANGCI_BUILD_TOOLCHAIN) GOBIN=$(CURDIR)/bin/tools GOFLAGS=-mod=mod \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@$(GOLANGCI_LINT) version 2>/dev/null | grep -q "built with $(GOLANGCI_BUILD_TOOLCHAIN) " || { \
		echo "ERROR: $(GOLANGCI_LINT) was not built with $(GOLANGCI_BUILD_TOOLCHAIN) (go.mod's toolchain)."; \
		echo "       Rebuild it: rm -f $(GOLANGCI_LINT) && make $(GOLANGCI_LINT)"; \
		$(GOLANGCI_LINT) version; \
		exit 1; }

# Baseline revision for the incremental lint gate. PRs lint against the
# merge-base with origin/main; override for local branches as needed.
LINT_BASE ?= origin/main

# lint — the BLOCKING gate (#131). Runs the full golangci-lint suite but
# reports only NEW issues since LINT_BASE, so any pre-existing backlog is
# baselined by construction (nothing to burn down up front) while any new
# violation on touched lines fails. This is the same invocation the CI
# `lint` job uses, and mirrors gibson/setec/sdk's own `lint` targets.
.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run the repo-pinned golangci-lint (blocking; new since LINT_BASE).
	@echo "Running linter (blocking; new since $(LINT_BASE))..."
	$(GOLANGCI_LINT) run --new-from-merge-base=$(LINT_BASE) ./...

# lint-all — full-tree, non-baselined. Surfaces the entire backlog, if any.
.PHONY: lint-all
lint-all: $(GOLANGCI_LINT) ## Run golangci-lint across the whole tree (informational).
	@echo "Running linter (full tree; informational)..."
	$(GOLANGCI_LINT) run ./...

# check: org Makefile contract CI-equivalent gate (gibson#171 slice 1.4 /
# zeroroot-ai/.github#87). golangci-lint is deliberately EXCLUDED here: a
# whole-module run is ~3 GB resident, a full core for minutes, and several
# of these repos share one workstation. CI now runs it directly
# (go-ci.yml calls `make lint`), so nothing is lost — this matches gibson
# (#1268), setec (#162) and sdk (#449). Run `make lint` by hand when you
# want it.
.PHONY: check
check: test ## Run the local gate (test only — run 'make lint' separately).

.PHONY: image
image: ## Build the runner OCI image.
	docker build -t $(IMAGE) .

.PHONY: clean
clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR) coverage.out coverage.html

.PHONY: tidy
tidy: ## go mod tidy.
	go mod tidy
