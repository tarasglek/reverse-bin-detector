# `--as-app` Design

## Goal

Run one-off commands using the same environment, working directory, runtime sandbox, and namespace policy that `reverse-bin-detector` generates for an app. Primary uses include unit tests, migrations, maintenance jobs, cron jobs, REPLs, and interactive shells.

## CLI

```sh
reverse-bin-detector --as-app APP_DIR -- COMMAND [ARGS...]
```

Examples:

```sh
reverse-bin-detector --as-app ~/apps/demo -- deno test
reverse-bin-detector --as-app ~/apps/demo -- ./manage.py migrate
reverse-bin-detector --as-app ~/apps/demo -- /bin/bash -i
```

A command is required. Existing `reverse-bin-detector APP_DIR` JSON behavior remains unchanged.

## Behavior

The command receives exactly the detector-generated app environment. No terminal, locale, shell, or other caller variables are added. Detection still loads `.env` or decrypts `secrets.enc.json`, resolves transport variables, sets the app working directory, and applies the exact policy for the detected app kind.

Runtime isolation remains unchanged:

- app source has the same read-only access;
- writable paths remain limited to detector-approved paths;
- static and executable apps retain their respective network policies;
- PID, IPC, UTS, and private `/proc` namespaces remain enabled;
- failure never falls back to unsandboxed execution.

Tests and jobs that create state must write under an approved writable path such as `data/`.

## Execution Architecture

Landlock restrictions applied during detection cannot be removed. `--as-app` therefore uses two processes:

1. An unrestricted parent starts a restricted detector child.
2. The child detects the app and generates a validated launch plan containing the requested command.
3. The child returns the plan and exits.
4. The parent changes to the generated working directory and executes the generated `unshare` and `landrun` command with inherited standard streams.

The custom command is inserted before runtime wrapping. The implementation must not parse and replace a command suffix in existing shell text.

## Process Semantics

`--as-app`:

- works without a TTY;
- inherits stdin, stdout, and stderr;
- returns the executed command's exit status;
- propagates termination signals and cleans up namespace children;
- does not daemonize;
- reloads app environment and secrets for every invocation.

Scheduling and overlap control remain external concerns. Cron or systemd timers invoke `--as-app`; `flock` or scheduler policy prevents overlapping jobs when needed.

## Identity and Path Scope

`--as-app` reproduces detector-generated per-app isolation for the supplied path and caller. It does not independently reproduce service-wide systemd settings or change to the packaged `reverse-bin` account. Full production parity requires invoking it with the production identity, canonical app path, service `PATH`, and SOPS environment.

## Testing

Cover:

- unchanged JSON mode;
- argument-boundary preservation after `--`;
- exact generated environment with no caller-variable leakage;
- working directory;
- app-kind filesystem and network policy;
- read-only source and writable `data/` behavior;
- noninteractive stdio and exit-code propagation;
- signal handling and namespace cleanup;
- encrypted environment loading;
- closed failure when Landlock or namespace setup fails.

## Scope

Do not update the reverse-bin agent skill. Do not add scheduling, overlap prevention, implicit shell selection, or service-account switching to the detector.

## Known limitation: Landlock does not mediate metadata syscalls

Landlock only restricts path-based data operations: open for read/write/execute, create, unlink, rename, make-dir, and truncate. It does not hook pure metadata syscalls such as `stat`, `chmod`, `chown`, `utimensat`, or `readlink`. GNU `touch` on an existing file succeeds inside the sandbox (it only calls `utimensat`), and an app running under the caller UID can `chmod a=rw` any file it owns even outside its allowlist, permanently loosening host permissions.

This is a Landlock ABI limit, not a detector or landrun bug; no Landlock rule can express "deny setattr while allowing read". Only mount-based sandboxes (read-only bind mounts, private tmpfs → `EROFS`) block these calls. Do not run untrusted code through `--as-app` under a privileged UID. Service key permissions must be enforced by systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, explicit `ReadWritePaths`).
