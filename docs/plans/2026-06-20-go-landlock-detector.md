# Go Landlock Detector Plan — TL;DR Checklist

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement checklist top-down.
> **Do not commit this plan.** Treat it as a local working document only.
> Commit implementation code, tests, docs, CI, and packaging changes normally, but always exclude this plan file from commits.

**Goal:** Move `discover-app.py` into this new Go repo. Detector emits the same JSON contract Caddy expects. Detection runs Landlock read-only. Detection may bind/listen on TCP sockets when required for port allocation, but outgoing connections are denied.

**Repos touched:**

- `.` — new Go detector
- `../reverse-bin-hosting` — package/use new detector
- `../caddy-reverse-bin` — owns shared detector schema contract

---

## Must preserve

- JSON fields Caddy accepts:
  - `executable`
  - `working_directory`
  - `envs`
  - `reverse_proxy_to`
  - `health_method`
  - `health_path`
  - `health_status`
- App types:
  - `main.ts` → Deno serve
  - executable `main.py` → run `./main.py`
  - `index.html` → Caddy file server root `.`
  - `dist/index.html` → Caddy file server root `dist`
- Env files:
  - `.env`
  - `secrets.enc.json` via `sops`
  - reject both together
- Config keys:
  - `REVERSE_BIN_COMMAND`
  - `LISTEN`
  - `REVERSE_BIN_HOST`
  - `REVERSE_BIN_PORT`
  - `SOCKET_PATH`
  - `REVERSE_BIN_HEALTH_METHOD`
  - `REVERSE_BIN_HEALTH_PATH`
  - `REVERSE_BIN_HEALTH_STATUS`

---

## Network/security model

- Preserve old detector behavior for TCP port allocation by allowing bind/listen during detection.
- Deny outgoing network connections during detection.
- Keep detection filesystem read-only.
- Therefore:
  - `REVERSE_BIN_PORT=` blank continues to allocate a free TCP port by binding locally
  - `LISTEN=` blank continues to allocate a free TCP port by binding locally
  - Python apps may use the default `SOCKET_PATH=data/reverse-bin.sock`
  - TCP-only apps may use explicit ports or blank TCP config for detector-selected ports

2026-07-05 follow-up: Caddy file-server supports `--listen unix///path.sock`. Static apps should always use reverse-bin-managed Unix sockets under `/run/reverse-bin/static-apps/app-<hash>/`, reject TCP listener config, and never need TCP bind permission.

---

## Checklist

### 1. Make Go repo skeleton

- [x] `cd .`
- [x] `go mod init github.com/tarasglek/reverse-bin-detector`
- [x] Add CLI: `cmd/reverse-bin-detector/main.go`
- [x] Add package: `internal/detector`
- [x] Add `Makefile` with `test`, `build`, `check`
- [x] Run `go test ./...`
- [x] Commit: `chore: create reverse-bin detector module`

### 2. Extract shared Caddy detector schema

- [x] In `../caddy-reverse-bin`, create tiny nested module/package `detectorschema`
- [x] Add `../caddy-reverse-bin/detectorschema/go.mod` with module path `github.com/tarasglek/caddy-reverse-bin/detectorschema`
- [x] Move/export detector JSON contract type from `../caddy-reverse-bin/detector.go` into `../caddy-reverse-bin/detectorschema`
- [x] Include strict parse/validate helpers in `detectorschema`
- [x] Keep dependencies minimal so detector does not pull Caddy's full dependency graph
- [x] Keep JSON field names unchanged:
  - [x] `executable`
  - [x] `working_directory`
  - [x] `envs`
  - [x] `reverse_proxy_to`
  - [x] `health_method`
  - [x] `health_path`
  - [x] `health_status`
- [x] Update `../caddy-reverse-bin` to import/use `detectorschema.DetectorOutput`
- [x] Update schema generator to reflect `detectorschema.DetectorOutput`
- [x] Run `cd ../caddy-reverse-bin && go test ./...`
- [x] Commit in `../caddy-reverse-bin`: `feat(detector): expose detector schema package`

### 3. Use shared detector schema in Go detector

- [x] Add dependency on `github.com/tarasglek/caddy-reverse-bin/detectorschema`
- [x] During local development, add temporary `replace github.com/tarasglek/caddy-reverse-bin/detectorschema => ../caddy-reverse-bin/detectorschema`
- [x] Emit `detectorschema.DetectorOutput`
- [x] Write test: CLI output parses with `detectorschema.Parse` and has no unknown fields
- [x] Run tests
- [x] Commit: `feat(detector): use caddy detector schema`

### 4. Create Python detector behavior test matrix

- [x] Treat `../reverse-bin-hosting/utils/discover-app/test_discover_app.py` as the behavior source for the Go detector
- [x] Create `docs/python-detector-test-matrix.md` mapping Python tests to Go test groups:
  - [x] detector JSON shape and health override fields
  - [x] env config parsing, including partial config and invalid combinations
  - [x] `.env` and `secrets.enc.json` source selection
  - [x] explicit command handling
  - [x] blank `LISTEN` and `REVERSE_BIN_PORT` free-port allocation
  - [x] `SOCKET_PATH` handling and absolute path rejection
  - [x] app entrypoint detection order
  - [x] child env construction and override behavior
  - [x] Deno app behavior, preserving Smallweb-compatible permissive flags
  - [x] CLI success/error behavior
- [x] Port each test group inside the corresponding implementation task, not all upfront
- [x] Keep Go test names close to Python test names where practical
- [x] Document any intentional behavior difference in the Go test that asserts it
- [x] Commit: `docs(detector): map python detector behavior tests`

### 5. Port `.env` loading

- [x] Test `.env` loads
- [x] Test blank values preserved: `REVERSE_BIN_PORT=`
- [x] Test `secrets.enc.json` loads through injected decrypt fn
- [x] Test `.env` + `secrets.enc.json` errors
- [x] Implement env source loader
- [x] Run tests
- [x] Commit: `feat(detector): load app env files`

### 6. Port env config parser

- [x] Test `REVERSE_BIN_COMMAND="python3 server.py"` → `sh -c ...`
- [x] Test `LISTEN=8080`
- [x] Test `REVERSE_BIN_HOST/PORT`
- [x] Test `SOCKET_PATH`
- [x] Test health method/path/status
- [x] Test bad combos error:
  - [x] `LISTEN` + `SOCKET_PATH`
  - [x] `LISTEN` + `REVERSE_BIN_PORT`
  - [x] partial health config
  - [x] bad status
- [x] Implement parser
- [x] Run tests
- [x] Commit: `feat(detector): parse app config`

### 7. Port app detection with local provider structure

- [x] Do not import CNB, Nixpacks, Herokuish, Paketo, or other app detector libraries
- [x] Add lightweight local provider interface inspired by Nixpacks/CNB detector patterns:

```go
type Provider interface {
    Name() string
    Detect(ctx Context) (Match, bool, error)
    Build(ctx Context, match Match, transport Transport) (detectorschema.DetectorOutput, error)
}
```

- [x] Preserve current detection order:
  - [x] explicit env command/config
  - [x] `main.ts`
  - [x] executable `main.py`
  - [x] `index.html`
  - [x] `dist/index.html`
- [x] Test `main.ts`
- [x] Test executable `main.py`
- [x] Test non-executable `main.py` ignored
- [x] Test `index.html`
- [x] Test `dist/index.html`
- [x] Test no entrypoint error
- [x] Keep broader Nixpacks-style heuristics out of scope for this port
- [x] Implement detection providers
- [x] Run tests
- [x] Commit: `feat(detector): detect app entrypoints`

### 8. Resolve transport with outgoing-network denial

- [x] Test explicit TCP works:
  - [x] `REVERSE_BIN_PORT=7777`
  - [x] `LISTEN=7777`
- [x] Test blank TCP allocates a free local port by listening:
  - [x] `REVERSE_BIN_PORT=`
  - [x] `LISTEN=`
- [x] Test socket works:
  - [x] `SOCKET_PATH=data/app.sock`
- [x] Test absolute socket path errors
- [x] Test missing transport:
  - [x] Python detected app → default `SOCKET_PATH=data/reverse-bin.sock`
  - [x] Deno app → detector-selected TCP port unless explicit TCP config provided
  - [x] Historical behavior: static apps used a detector-selected TCP port for child Caddy file-server unless explicit TCP config was provided; superseded by the 2026-07-05 follow-up above.
- [x] Implement transport resolver
- [x] Ensure any port probe uses listen/bind only, no outgoing dial
- [x] Run tests
- [x] Commit: `feat(detector): resolve transport without outgoing network`

### 9. Build backend command + envs

- [x] Test Deno command
- [x] Test Python command
- [x] Test file-server commands
- [x] Test env output `KEY=value`
- [x] Test `PATH` copied if missing
- [x] Test `HOME=<app>/data` if `data/` exists
- [x] Test `DENO_NO_UPDATE_CHECK=1`
- [x] Implement command/env builder
- [x] Run tests
- [x] Commit: `feat(detector): build backend config`

### 10. Add minimal DRY sandbox policy model

- [x] Add `internal/sandbox/policy.go`
- [x] Define minimal pledge/unveil/Landlock/Deno-inspired policy structs:

```go
type Policy struct {
    ReadOnly       []string
    ReadWrite      []string
    AllowTCPBind   bool
    DenyTCPConnect bool
}
```

- [x] Add shared path helpers:
  - [x] `SystemReadOnlyPaths()` → existing system/runtime read paths such as `/bin`, `/usr`, `/lib`, `/lib64`, `/etc`
  - [x] `AppReadOnlyPath(appDir)`
  - [x] `AppDataReadWritePath(appDir)` only when `data/` exists or runtime should create/use it
  - [x] `SOPSReadOnlyPaths(env)` only when `SOPS_AGE_KEY_FILE` is set
- [x] Add policy constructors that compose shared helpers instead of duplicating lists:
  - [x] `DetectionPolicy(appDir, env)` → app/system/SOPS read-only, no writes, TCP bind allowed, TCP connect denied
  - [x] `PythonRuntimePolicy(appDir, transport)` → app/system read-only, `data/` read-write, TCP bind only when transport needs it, TCP connect denied
  - [x] `DenoRuntimePolicy(appDir, denoPath, denoCache, transport)` → Smallweb-compatible runtime policy for now; app/system/Deno paths read-only, `data/` read-write, TCP bind allowed for TCP transport, TCP connect not denied yet
  - [x] `StaticPolicy(appRoot)` → app root read-only; no child runtime policy needed
- [x] Centralize Deno arg generation in one function preserving Smallweb-compatible permissive flags
- [x] Add comments noting future NetBSD pledge/unveil mapping
- [x] Add table-driven tests for policy constructors
- [x] Run tests
- [x] Commit: `feat(detector): add minimal sandbox policy model`

### 11. Add detection Landlock

- [x] Add dependency: `github.com/landlock-lsm/go-landlock`
- [x] Add `internal/sandbox`
- [x] Apply Landlock early in `Run()` after app dir resolved using `DetectionPolicy`
- [x] Allow read-only:
  - [x] app dir
  - [x] `/bin`
  - [x] `/usr`
  - [x] `/lib`
  - [x] `/lib64`
  - [x] `/etc`
  - [x] needed `PATH` dirs
  - [x] `SOPS_AGE_KEY_FILE` path if set
- [x] Allow no writes
- [x] Allow TCP bind/listen when detector must allocate or validate a listening port
- [x] Do not bind Unix sockets during detection; socket paths are emitted for the runtime app to create
- [x] Deny outgoing TCP connect/dial
- [x] Strict mode: fail if Landlock outgoing TCP deny unavailable
- [x] Dev/test flag: `--allow-unsafe-no-landlock`
- [x] Subprocess tests:
  - [x] read app file OK
  - [x] write app file denied
  - [x] read outside allowlist denied
  - [x] TCP listen allowed
  - [x] TCP dial denied
- [x] Run tests
- [x] Commit: `feat(detector): sandbox detection with landlock`

### 12. Add SOPS support under Landlock

- [x] Resolve `sops` with `exec.LookPath` before applying Landlock
- [x] Resolve `SOPS_AGE_KEY_FILE` before applying Landlock when set
- [x] Include resolved `sops` path, needed `PATH` dirs, and age key path in `DetectionPolicy`
- [x] Allow read/execute path for `sops`
- [x] Allow read for age key file
- [x] Run `sops --decrypt --input-type json --output-type dotenv <file>`
- [x] Capture stderr on failure
- [x] Test with fake `sops`
- [x] Run tests
- [x] Commit: `feat(detector): decrypt sops env files`

### 13. Runtime sandbox output

- [x] Keep runtime separate from detection
- [x] First version may still emit `landrun ... app`
- [x] Add `--no-runtime-sandbox`
- [x] Test emitted runtime wrapper has:
  - [x] app dir read-only
  - [x] `data/` read-write
  - [x] only needed TCP bind port
  - [x] no broader network than the resolved runtime policy
- [x] Document: direct Landlock runtime needs child helper
- [x] Commit: `feat(detector): emit runtime sandbox command`

### 14. End-to-end CLI tests

- [x] Test Python socket app CLI output
- [x] Test static TCP app CLI output
- [x] Test invalid app exits non-zero
- [x] Validate JSON against Caddy contract shape
- [x] Run `make check`
- [x] Commit: `test(detector): verify cli output`

### 15. Add GitHub CI and release automation

Mirror the useful parts of `../caddy-reverse-bin` CI, scaled down for this detector.

- [x] Add `.github/workflows/test-go.yaml`
  - [x] Trigger on Go/module/Makefile/workflow changes
  - [x] Use `actions/checkout`, `actions/setup-go`, Go module/build cache
  - [x] Run `make check`
- [x] Add `.github/workflows/lint-go.yaml`
  - [x] Run `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
  - [x] Run `golangci/golangci-lint-action`
- [x] Add `.github/workflows/lint-github-actions.yaml`
  - [x] Run actionlint
  - [x] Run zizmor advisory/security lint like `../caddy-reverse-bin`
- [x] Add `.github/workflows/release.yml`
  - [x] Trigger on `v*` tags
  - [x] Run GoReleaser with `GITHUB_TOKEN`
- [x] Add `.github/dependabot.yml` for GitHub Actions updates
- [x] Add `.goreleaser.yaml`
  - [x] Build `./cmd/reverse-bin-detector`
  - [x] Produce Linux amd64/arm64 binaries at minimum
  - [x] Set version/commit/date ldflags if version variables exist
  - [x] Use binary archives and checksums
- [x] Add `make release-dry-run`
- [x] Run CI-equivalent local checks where possible:
  - [x] `make check`
  - [x] `make release-dry-run`
- [x] Commit implementation/CI files, excluding this plan: `chore(ci): add detector github workflows`

### 16. Publish detector to GitHub

- [x] Create/push GitHub repository `github.com/tarasglek/reverse-bin-detector`
- [x] Ensure `go.mod` module path is `github.com/tarasglek/reverse-bin-detector`
- [x] Remove any local-only `replace` directives from detector `go.mod`
- [x] Tag an initial version, e.g. `v0.1.0`
- [x] Verify clean checkout can build from GitHub:
  - [x] `go install github.com/tarasglek/reverse-bin-detector/cmd/reverse-bin-detector@v0.1.0`
  - [x] `reverse-bin-detector --version`
- [x] Commit/tag/push complete detector source and docs
- [x] Commit: `chore: prepare detector github release`

### 17. Hook into `reverse-bin-hosting`

- [x] Build detector from GitHub tag in `scripts/fetch-runtimes.sh`
- [x] Add detector version/source to `packaging/runtime-versions.env`
- [x] Install binary in `debian/install`
- [x] Change Caddyfiles:

```caddyfile
dynamic_proxy_detector "/usr/lib/reverse-bin/reverse-bin-detector" "{reverse_bin_app_dir}"
```

- [x] Remove Python detector from package
- [x] Update README: `discover-app.py` → `reverse-bin-detector`
- [x] Add README credits/inspiration note:
  - [x] Smallweb for simple app-directory hosting and Deno runtime shape
  - [x] Nixpacks for provider-style source detection patterns
  - [x] Cloud Native Buildpacks/Heroku buildpacks for detect-phase concepts
  - [x] pledge/unveil/Landlock/Deno permission models for sandbox policy vocabulary
- [x] Run `make fetch-runtimes`
- [x] Run `make deb`
- [x] Commit: `feat(packaging): use go detector`

### 18. Local package replacement smoke test

This is the acceptance gate: the Go detector works when the Python detector is removed from `../reverse-bin-hosting`, the Debian package is rebuilt, installed locally, and existing apps still work.

- [x] Confirm `../reverse-bin-hosting` no longer packages or references `utils/discover-app/discover-app.py`
- [x] Rebuild package from `../reverse-bin-hosting` with the Go detector fetched from its GitHub tag:
  - [x] `make fetch-runtimes`
  - [x] `make deb`
- [x] Install rebuilt `.deb` locally on test host
- [x] `dpkg-query -W reverse-bin`
- [x] Confirm installed files include `/usr/lib/reverse-bin/reverse-bin-detector`
- [x] Confirm installed files do not include `/usr/lib/reverse-bin/discover-app.py`
- [x] `systemctl restart reverse-bin.service`
- [x] `systemctl is-active reverse-bin.service`
- [x] Smoke existing app types:
  - [x] Python Unix-socket app still responds
  - [x] Deno app still responds
  - [x] static root `index.html` app still responds through child Caddy file-server
  - [x] static `dist/index.html` app still responds through child Caddy file-server
  - [x] app with `.env` still responds
  - [x] app with `secrets.enc.json` still responds when SOPS key is configured
- [x] `curl https://python3-unix-echo.<domain>/ | python3 -m json.tool`
- [x] Confirm app JSON response
- [x] Confirm detector no writes and no outgoing network in tests

---

## Later: remove `landrun` fully

Need separate helper because Landlock sticks to process.

Shape:

```text
Caddy launches app command:
reverse-bin-sandbox-exec --ro APP --rw APP/data --bind-tcp 7777 -- app args...
```

Checklist:

- [ ] Add `cmd/reverse-bin-sandbox-exec`
- [ ] Helper applies Landlock
- [ ] Helper `syscall.Exec`s app
- [ ] Test file/network restrictions
- [ ] Detector emits helper instead of `landrun`
- [ ] Hosting stops bundling `landrun`

---

## Final verify

```bash
cd . && make check
cd ../caddy-reverse-bin && go test ./...
cd ../reverse-bin-hosting && make fetch-runtimes && make deb
```

Then staging smoke test.
