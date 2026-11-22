# reverse-bin-detector

Turns an app directory into the `App` that [reverse-bin](https://github.com/tarasglek/caddy-reverse-bin) runs: command, sandbox, environment, address and readiness. Packaged by [reverse-bin-hosting](https://github.com/tarasglek/reverse-bin-hosting), whose Caddyfile calls it per request host.

```sh
reverse-bin-detector [--public-host=HOST] APP_DIR                          # print the App as JSON
reverse-bin-detector [--public-host=HOST] --as-app[-dev] APP_DIR -- CMD...  # run CMD in the app's sandbox
```

## App kinds

| Kind | Detected by | Runs |
|---|---|---|
| explicit | `REVERSE_BIN_COMMAND` | `sh -c "$REVERSE_BIN_COMMAND"` |
| deno | `main.ts` | `deno serve --watch --allow-all --host $REVERSE_BIN_HOST --port $REVERSE_BIN_PORT main.ts` |
| static | `index.html` or `dist/index.html` | `reverse-bin-caddy file-server` on `/run/reverse-bin/static-apps/app-<hash>/reverse-bin.sock` |

Apps listen on TCP: they get `REVERSE_BIN_HOST` and `REVERSE_BIN_PORT` (a free loopback port unless they set it). With `SOCKET_PATH` (relative, inside the app dir) an app listens on that unix socket instead. The detector creates a socket's directory, and the launched command removes a stale socket first.

## App configuration

The app's `.env`, or `secrets.enc.json` decrypted by sops (age key from `SOPS_AGE_KEY_FILE`), not both. Every key reaches the app, plus the listener variables above, `REVERSE_BIN_PUBLIC_HOST`, and `HOME=<app>/data`, `TMPDIR=data`, `PATH` unless set.

| Key | Meaning | Default |
|---|---|---|
| `REVERSE_BIN_COMMAND` | Shell command instead of the detected kind | — |
| `REVERSE_BIN_HOST`, `REVERSE_BIN_PORT` | TCP address to listen on | `127.0.0.1`, a free port |
| `SOCKET_PATH` | Unix socket to listen on instead | TCP |
| `REVERSE_BIN_HEALTH_PATH` | Readiness request path; empty: ready once it accepts a connection | `/` |
| `REVERSE_BIN_HEALTH_METHOD` | Its method | `HEAD` |
| `REVERSE_BIN_HEALTH_STATUS` | Status it must answer, `200` or `2xx` | any response |
| `REVERSE_BIN_PUBLIC_HOST` | Public host the app is served at over https; overrides `--public-host` | from Caddy |

Any other `REVERSE_BIN_*` key is an error.

## Sandbox

`unshare --pid --kill-child` (descendants die with the app) around [landrun](https://github.com/zouuup/landrun), with `sh` as the namespace's PID 1 so the app itself gets SIGTERM (PID 1 ignores signals it has no handler for): the app dir read-only and executable, `data/` writable, network allowed except for static apps. Requires kernel Landlock ABI ≥ 6 (Linux 6.12+); the detector refuses to plan without it. App files are read through `os.Root`, so a symlink out of the app dir is an error; sops runs under landrun with no network. `--as-app-dev` makes the source writable.

## Per-app SSH: `rb-ssh`

Invoked as `rb-ssh`, the detector maps an SSH key to an app and runs the session in its `--as-app-dev` sandbox. Each `authorized_keys` line names its app:

```
restrict,pty,command="/usr/lib/reverse-bin/rb-ssh todo" ssh-ed25519 AAAA... todo
```

It accepts only `rb-ssh APP` or `rb-ssh -c "<dir>/rb-ssh APP"` (it is also the service user's login shell). No `SSH_ORIGINAL_COMMAND` starts `bash -i`; otherwise `sh -c "$SSH_ORIGINAL_COMMAND"`, which is how `git push reverse-bin@host:.` reaches the checkout. sftp and scp are refused. `PATH`, the apps root and the age key path are compiled in.

## Development

```sh
make check   # vet, gofmt, tests (landrun-backed ones skip without landrun)
```

To release `vX.Y.Z`: write `release-notes/vX.Y.Z.md` (at most 100 words), run `make release-notes TAG=vX.Y.Z` and `make deps-check` (commit any diff), then push the tag.
