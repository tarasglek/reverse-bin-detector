.PHONY: test build check

test:
	go test ./...

build:
	go build ./cmd/reverse-bin-detector

check: test build
