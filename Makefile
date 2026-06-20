.PHONY: test build check release-dry-run

test:
	go test ./...

build:
	go build ./cmd/reverse-bin-detector

check: test build

release-dry-run:
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
