# Release process

Before pushing tag `vX.Y.Z`:

1. Add `release-notes/vX.Y.Z.md`: at most 100 words, dense and terse.
2. Run `make check`, `make release-notes TAG=vX.Y.Z`, and `make deps-check`. deps-check updates Go modules, the Go toolchain, and GitHub Actions to latest and runs `go fix`; commit any diff it leaves.

Tagged CI reruns both checks before GoReleaser publishes the notes as the release body.
