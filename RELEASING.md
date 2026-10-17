# Releasing

openaudit ships as one npm package, `@openaudit/cli`, built from `apps/cli`. The build (`apps/cli/scripts/build.ts`) bundles the CLI and the unpublished `@openaudit/*` workspace packages into `apps/cli/dist/cli.js`. Third-party packages stay as ordinary `dependencies`, so `typescript` (used by `code.typecheck`) and the optional `playwright-core` and `axe-core` are installed by npm/Bun as usual. `apps/cli/bin/openaudit.js` is a small Node-compatible launcher: under Bun it loads the bundle, under Node (`npx`) it hands over to a `bun` on PATH or prints how to install Bun.

If you add a dependency to `core`, `auditors`, `agent` or `mcp`, add it to `apps/cli/package.json` too. The build fails with a list if one is missing.

## Check a release locally

```sh
bun run release:check                  # versions agree, bundle builds
cd apps/cli && npm pack --dry-run      # should list 5 files, about 350 kB
```

The version lives in two places that must match: `apps/cli/package.json` and `VERSION` in `packages/core/src/engine.ts`. `release:check` fails if they differ, and in CI also if the tag differs.

## First publish (manual)

The package name does not exist yet, so trusted publishing cannot be configured until the first version is on npm.

```sh
npm login
cd apps/cli
bun run build
npm publish --access public
```

Provenance is only generated from CI, so this first version has none; every tag-driven release after it does.

Try it from a clean directory: `bunx @openaudit/cli --version`.

## Set up trusted publishing (once, after the first publish)

1. Open https://www.npmjs.com/package/@openaudit/cli/access (Settings, Trusted Publisher).
2. Choose GitHub Actions and enter: organization or user `wezter96`, repository `openaudit`, workflow filename `release.yml`. Leave the environment empty.
3. Optionally set "Require two-factor authentication and disallow tokens" under publishing access, so only the workflow can publish.

No npm token is stored in GitHub. The workflow gets a short-lived OIDC credential through `permissions: id-token: write`.

If you would rather publish the first version from CI, create an automation token on npmjs.com, store it as the `NPM_TOKEN` repository secret, and uncomment the `NODE_AUTH_TOKEN` line in `.github/workflows/release.yml`. Remove the secret and that line once trusted publishing works.

## Cut a release

```sh
# 1. Bump both versions to the same number
$EDITOR apps/cli/package.json packages/core/src/engine.ts
bun run release:check

# 2. Commit and tag
git commit -am "Release 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

Pushing the tag runs `.github/workflows/release.yml`:

1. `verify`: tag matches the version, Biome, types, tests.
2. `publish`: builds, runs `npm publish --provenance --access public` and creates a GitHub Release whose notes come from the commit subjects since the previous tag.

Tags with a hyphen (`v0.3.0-rc.1`) publish to the `next` dist-tag and are marked as pre-releases on GitHub.

If the publish step fails after the tag exists, fix the cause, delete the tag (`git push --delete origin v0.2.0`; `git tag -d v0.2.0`) and tag again. A version that did reach npm cannot be reused: bump it.

## Release notes

`apps/cli/scripts/release-notes.ts` writes the notes, one bullet per commit subject, so write each subject for someone reading the release page and keep the reasons in the body. The type picks the section: `feat` is Added, `fix` is Fixed, `perf` and `revert` are Changed, `docs` is Documentation, and any type with the `security` scope is Security. A scope prints as a `[scope]` prefix, and a subject that isn't conventional lands under Changed as written.

Users never see `chore`, `ci`, `build`, `refactor`, `style` or `test` commits, merges, the `Release x.y.z` bump, or the `site`, `badge` and `badge-scanner` scopes, which don't ship in the npm package. A breaking change (`feat!:` or a `BREAKING CHANGE:` footer) is always published, marked **BREAKING**.

Preview the notes before you tag, or check them for a tag you made locally:

```sh
bun apps/cli/scripts/release-notes.ts HEAD     # what the next release would say
bun apps/cli/scripts/release-notes.ts v0.3.1   # the notes for an existing tag
```
