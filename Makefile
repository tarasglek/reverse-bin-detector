GOVULNCHECK ?= go run golang.org/x/vuln/cmd/govulncheck@latest
PINACT ?= go run github.com/suzuki-shunsuke/pinact/v5/cmd/pinact@latest
NOTES_MAX_WORDS ?= 100

# Fixers rewrite the same files; never run targets in parallel.
.NOTPARALLEL:

.PHONY: test build check deps-check deps-latest modernize vulncheck release-notes release-dry-run

test:
	go test ./...

build:
	go build ./cmd/reverse-bin-detector

check: test build

# deps-latest and modernize rewrite files; deps-check fails when they did.
# Run it locally and commit the result.
deps-latest:
	go get -u -t ./... && go get toolchain@latest && go mod tidy
	$(PINACT) run -u

modernize:
	go fix ./...

# Fails only on vulnerabilities reachable from our code.
vulncheck:
	$(GOVULNCHECK) ./...

deps-check: deps-latest modernize vulncheck
	@if [ -n "$$(git status --porcelain)" ]; then git status --short; git diff; \
	echo "error: fixers changed files; commit them" >&2; exit 1; fi

# Usage: make release-notes TAG=vX.Y.Z
release-notes:
	@test -n "$(TAG)" || { echo "usage: make release-notes TAG=vX.Y.Z" >&2; exit 1; }
	@f=release-notes/$(TAG).md; [ -s "$$f" ] || { echo "error: $$f missing" >&2; exit 1; }; \
	n=$$(wc -w < "$$f"); [ "$$n" -le $(NOTES_MAX_WORDS) ] || { \
	echo "error: $$f: $$n words > $(NOTES_MAX_WORDS). Rewrite caveman: fragments, no filler. Keep what changed, breaking, GO/CVE IDs." >&2; exit 1; }

release-dry-run:
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
