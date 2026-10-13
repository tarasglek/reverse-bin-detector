# reverse-bin-detector

Detect app kind, build env, generate sandbox launch plan for [reverse-bin-hosting](https://github.com/tarasglek/reverse-bin-hosting).

## What it does

- Read app dir: `.env` or SOPS `secrets.enc.json`
- Detect kind: deno, python, static, explicit `REVERSE_BIN_COMMAND`
- Emit landrun/namespace launch JSON for Caddy

Full docs: **reverse-bin-hosting README** — https://github.com/tarasglek/reverse-bin-hosting

## Build

```sh
make build          # or: go build ./cmd/reverse-bin-detector
./reverse-bin-detector --version
```

## Dev-run

```sh
./reverse-bin-detector ~/apps/demo | jq
```

## `--as-app`: run a command as an app

`--as-app` runs a command with the detector-generated app sandbox, environment, and working directory.

Shell in (interactive):

```sh
./reverse-bin-detector --as-app ~/apps/demo -- /bin/bash -i
```

Non-interactive (e.g. does the app's runtime allow this?):

```sh
./reverse-bin-detector --as-app ~/apps/demo -- curl https://example.com
./reverse-bin-detector --as-app ~/apps/demo -- sh -c 'wget -q -O- http://127.0.0.1; echo rc=$?'
./reverse-bin-detector --as-app ~/apps/demo -- deno test
```

Full production example (sudo, service identity, keys): see **reverse-bin-hosting README → "Interactive sandbox shells"**.

### Per-app SSH (`rb-ssh`)

Invoked through an `rb-ssh` symlink, the detector maps an SSH key to an app sandbox. Each `authorized_keys` line names its app:

```
restrict,pty,command="/usr/lib/reverse-bin/rb-ssh todo" ssh-ed25519 AAAA... todo
```

`rb-ssh` is also the service user's login shell, so it accepts only `rb-ssh APP` or `rb-ssh -c "<dir>/rb-ssh APP"` and refuses anything else. No `SSH_ORIGINAL_COMMAND` starts `bash -i`; otherwise it runs `sh -c "$SSH_ORIGINAL_COMMAND"`. sftp and scp are refused. `PATH`, the apps root, and the age key path are compiled in, not taken from the session. Packaging lives in reverse-bin-hosting.

## Build/check

```sh
make check        # test + build + release gate
make release-dry-run
```