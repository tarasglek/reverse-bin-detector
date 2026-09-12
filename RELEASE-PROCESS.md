# Release process

Detector releases use human-authored release notes. Before pushing a version tag:

1. Add `release-notes/<tag>.md`, where `<tag>` is the exact tag (for example, `v1.2.3`).
2. Start the file with `# Reverse Bin Detector vX.Y.Z`.
3. Include non-empty `## Highlights`, `## Breaking changes`, and `## Full list of changes` sections. Highlights and Full list of changes must each contain at least one `- ` bullet. Write `None.` under Breaking changes when applicable.
4. Run `make check`, then push the matching tag.

Tagged CI validates `release-notes/<tag>.md` before GoReleaser runs. A missing or malformed file stops publication, and the validated file becomes the GitHub release body.
