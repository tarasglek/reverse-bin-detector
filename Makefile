.PHONY: test build check release-check release-dry-run

test:
	go test ./...

build:
	go build ./cmd/reverse-bin-detector

check: test build release-check

release-check:
	./scripts/check-release-notes-test.sh
	./scripts/check-release-gate.sh

release-dry-run:
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
