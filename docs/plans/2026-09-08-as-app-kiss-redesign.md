# `--as-app` KISS Redesign

## Goal

Publish one safe command for running a one-off process with the environment, working directory, and runtime sandbox generated for an app:

```sh
reverse-bin-detector --as-app APP_DIR -- COMMAND [ARGS...]
```

The previously published `v0.1.13` release and tag were deleted. The old `--sandbox-exec` name is therefore not a compatibility boundary and will not be retained as an alias.

## Design

Keep the existing two-process security boundary because detection Landlock restrictions are irreversible:

1. An unrestricted parent invokes a restricted detector child.
2. The child loads app configuration and emits a schema-valid launch plan for the requested command.
3. The parent validates the plan, changes to its working directory, and executes its `unshare`/`landrun` command with inherited standard streams.

`--as-app` always uses the real runtime sandbox. Sandbox setup errors fail closed. There is no environment variable, test hook, or fallback that permits unsandboxed execution.

Set `HOME` to `<app>/data` when the app does not define it. This prevents interactive shells from falling back to the caller's account home. Keep this behavior in normal environment construction rather than adding a special warning path for `--as-app`.

## Tests and CI

Use one test suite. Tests contain no capability probes, dynamic capability adjustment, or capability-based skips.

GitHub-hosted Ubuntu can run every current test when the workflow:

1. installs the package-compatible `landrun v0.1.14` binary;
2. sets `kernel.apparmor_restrict_unprivileged_userns=0` when that AppArmor control exists;
3. runs the ordinary `make check` target.

This was verified by GitHub Actions run `34184380223`: user namespaces worked, all Landlock restriction cases passed, all seven `--as-app` sandbox E2E tests passed, and the full check passed.

Non-Linux Landlock tests remain excluded at compile time by their existing Go build constraint. A Linux host that cannot satisfy the runtime sandbox requirements fails the relevant tests rather than silently reducing coverage.

## Release and Hosting Order

1. Rewrite the unpublished detector history after `v0.1.12` into focused, bisectable patches.
2. Keep unrelated release-note CI infrastructure as an independent patch.
3. Remove the orphaned `release-notes/v0.1.13.md`; author fresh notes only when preparing the corrected release.
4. Release the corrected detector.
5. Update the detector pin in `reverse-bin-hosting`.
6. Only then commit the matching hosting documentation and security notes.
