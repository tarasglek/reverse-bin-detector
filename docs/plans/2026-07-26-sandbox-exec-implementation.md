# Sandbox Exec Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `--as-app APP_DIR -- COMMAND...` for one-off commands using exact detector-generated runtime environment and isolation.

**Architecture:** Restricted child builds custom launch plan; unrestricted parent validates and executes it. Existing JSON mode stays unchanged.

**Tech Stack:** Go, `detectorschema`, `os/exec`, Landlock, `landrun`, `unshare`

---

- [x] Task 1: Add custom-command launch-plan API
  - Files: `internal/detector/detector.go`, `internal/detector/detector_test.go`
  - Test first: custom command replaces app command before sandbox wrapping while env, working directory, transport, and app-kind policy remain unchanged.
  - Verify RED: `go test ./internal/detector -run 'TestResolve.*CustomCommand'` fails because API is absent.
  - Implement: add minimal resolver accepting explicit argument vector; reject empty command.
  - Verify GREEN: `go test ./internal/detector -run 'TestResolve.*CustomCommand'`.

- [x] Task 2: Parse sandbox-exec CLI without changing JSON mode
  - Files: `internal/detector/detector.go`, `cmd/reverse-bin-detector/main_test.go`
  - Test first: cover normal `APP_DIR`, `--as-app APP_DIR -- COMMAND...`, missing app, missing separator, and missing command.
  - Verify RED: focused CLI tests fail because flag is unknown.
  - Implement: strict argument parser preserving every command argument after `--`; update usage text.
  - Verify GREEN: `go test ./cmd/reverse-bin-detector ./internal/detector`.

- [x] Task 3: Generate plan in restricted child
  - Files: `cmd/reverse-bin-detector/main.go`, `internal/detector/detector.go`, relevant tests
  - Test first: child plan loads app env, contains custom wrapped command, and emits schema-valid JSON without executing command.
  - Verify RED: focused child-plan test fails because child mode is absent.
  - Implement: private re-exec mode; child applies detection Landlock, resolves custom plan, writes JSON, then exits. Parent validates child output with `detectorschema`.
  - Verify GREEN: `go test ./cmd/reverse-bin-detector ./internal/detector`.

- [x] Task 4: Execute plan with exact process semantics
  - Files: `cmd/reverse-bin-detector/main.go`, `cmd/reverse-bin-detector/e2e_test.go`
  - Test first: verify working directory, exact env/no caller leak, argument preservation, stdout/stderr, and exit status.
  - Verify RED: E2E sandbox-exec tests fail because parent does not execute plan.
  - Implement: inherit standard streams, set generated working directory, run generated executable, and propagate command exit status. No fallback.
  - Verify GREEN: `go test ./cmd/reverse-bin-detector -run SandboxExec`.

- [x] Task 5: Verify isolation and automation behavior
  - Files: `cmd/reverse-bin-detector/e2e_test.go`
  - Test first: source write fails, `data/` write succeeds for executable app, noninteractive invocation works, and namespace child dies on termination.
  - Verify RED: each new assertion must expose missing or incorrect behavior before its corresponding fix.
  - Implement: minimal signal/process handling fixes only where tests require them.
  - Verify GREEN: `go test ./cmd/reverse-bin-detector -run SandboxExec`.

- [x] Task 6: Document CLI, then run full gate
  - Files: `README.md` or CLI usage documentation; do not modify agent skills.
  - Document: tests, migrations, cron/systemd jobs, interactive shell, exact-env behavior, read-only source, writable `data/`, caller identity/path caveat.
  - Verify: `gofmt -w cmd internal && go vet ./... && go test ./... && make check`.
  - Expected: all commands pass; `git diff --check` reports no errors.
