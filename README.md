# reverse-bin-detector

Detect app kind, build env, generate sandbox launch plan for [reverse-bin-hosting](https://github.com/tarasglek/reverse-bin-hosting).

## What it does

- Read app dir: `.env` or SOPS `secrets.enc.json`
- Detect kind: deno, python, static, explicit `REVERSE_BIN_COMMAND`
- Emit landrun/namespace launch JSON for Caddy
- Sandbox: [landrun](https://github.com/zouuup/landrun) on PATH, kernel Landlock ABI ≥ 6 (Linux 6.12+); refuses to plan otherwise. App files are read via `os.Root`, so symlinks out of the app dir fail; sops decrypts from stdin under landrun with no network
- With `--public-host=app.example.com`, inject `REVERSE_BIN_PUBLIC_HOST` unless the app env sets it; the app is always served as `https://$REVERSE_BIN_PUBLIC_HOST` (use it for CSRF origins, OAuth redirects, absolute links; `${REVERSE_BIN_PUBLIC_HOST%%:*}` where a bare hostname is required)

Full docs: **reverse-bin-hosting README** — https://github.com/tarasglek/reverse-bin-hosting

## Build

```sh
make build          # or: go build ./cmd/reverse-bin-detector
./reverse-bin-detector --version
```

## Dev-run

```sh
./reverse-bin-detector ~/apps/demo | jq
./reverse-bin-detector --public-host=demo.example.com ~/apps/demo | jq .envs
```

## `--as-app` / `--as-app-dev`: run a command as an app

Both run `COMMAND` with the sandbox, environment, and working directory the
detector generates for the app. `--as-app` is the production sandbox: source
read-only, `data/` writable. `--as-app-dev` is the same sandbox with the app
source writable, for editing and `git push`; development only.

```sh
./reverse-bin-detector --as-app ~/apps/demo -- deno test
./reverse-bin-detector --as-app ~/apps/demo -- sh -c 'wget -q -O- http://127.0.0.1; echo rc=$?'
./reverse-bin-detector --as-app-dev ~/apps/demo -- /bin/bash -i
```

Production example (sudo, service identity, keys): see **reverse-bin-hosting README → "Interactive sandbox shells"**.

### Per-app SSH (`rb-ssh`)

Invoked through an `rb-ssh` symlink, the detector maps an SSH key to an app and runs the session as `--as-app-dev` (source writable). Each `authorized_keys` line names its app:

```
restrict,pty,command="/usr/lib/reverse-bin/rb-ssh todo" ssh-ed25519 AAAA... todo
```

`rb-ssh` is also the service user's login shell, so it accepts only `rb-ssh APP` or `rb-ssh -c "<dir>/rb-ssh APP"` and refuses anything else. No `SSH_ORIGINAL_COMMAND` starts `bash -i`; otherwise it runs `sh -c "$SSH_ORIGINAL_COMMAND"`, which is how `git push reverse-bin@host:.` reaches `git-receive-pack` inside the sandbox. sftp and scp are refused. `PATH`, the apps root, and the age key path are compiled in, not taken from the session. Packaging lives in reverse-bin-hosting.

## Build/check

```sh
make check        # test + build + release gate
make release-dry-run
```