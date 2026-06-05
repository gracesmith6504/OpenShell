# OpenShell Docs Website Branch

This branch contains the generated Fern documentation website for OpenShell.
It is intentionally separate from `main` and does not contain the OpenShell
application source tree.

## Purpose

`docs-website` is the publishable docs branch. The branch stores versioned Fern
snapshots so the docs site can serve the current release, current development
docs, and selected historical releases from one generated branch.

Do not use this branch for source changes. Update documentation source on
`main`, then sync the desired snapshot into this branch.

## Current Snapshots

| Version | Source |
| --- | --- |
| `latest` | `v0.0.57` |
| `dev` | `main` snapshot |
| `v0.0.36` | `v0.0.36` |

Expected routes:

- `/openshell/latest/...` renders the current release snapshot.
- `/openshell/dev/...` renders the current development docs snapshot.
- `/openshell/v0.0.36/...` renders the selected historical snapshot.

`latest` is a moving release alias. It is not a dedicated historical route for
the release tag it currently points at.

## Layout

```text
fern/
├── docs.yml
├── versions/
│   ├── dev.yml
│   ├── latest.yml
│   └── v0.0.36.yml
├── pages-dev/
├── pages-latest/
└── pages-v0.0.36/
```

`fern/docs.yml` defines the public version selector and the shared Fern site
configuration. Each `fern/versions/*.yml` file points navigation entries at the
matching `fern/pages-*` snapshot directory.

## Sync Model

The planned automation on `main` owns this branch:

1. `sync-docs.yml` checks out a source ref from `main` or a release tag.
2. The sync script copies `docs/**` into the selected `fern/pages-{slug}/`
   directory.
3. The sync script updates `fern/versions/{slug}.yml` and the version list in
   `fern/docs.yml`.
4. Fern validation runs before the generated changes are committed back to this
   branch.
5. `publish-docs-website.yml` publishes this branch to Fern in preview or
   production mode.

Historical snapshots are preserved until their slug is explicitly synced or
removed. Removing a version deletes only its `fern/pages-{slug}/` directory,
its `fern/versions/{slug}.yml` file, and its version selector entry.

## Validation

Run Fern validation:

```shell
mise run docs
```

Run a local Fern preview:

```shell
mise run docs:serve
```

If `FERN_TOKEN` is available, run a non-production hosted preview:

```shell
npx --yes fern-api@5.40.0 generate --docs --preview --id openshell-docs-website
```

## Included Root Files

The root `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md` files are copied from
`main` so the generated branch keeps the repository's normal license,
contribution, and security reporting signals.

## Branch Rules

Recommended protection for this branch:

- Prevent deletion.
- Prevent force pushes.
- Allow maintainers and the docs sync workflow to push generated updates.
- Avoid requiring normal pull request review for generated sync commits until
  the manual sync and publish path is proven stable.
