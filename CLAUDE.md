# effect-auth — working agreement

SPEC.md is the authoritative description of the library and REFACTOR.md of the in-flight
refactor. This file is only the toolchain contract; it does not restate either.

## Before you finish any change

```sh
pnpm fix     # oxlint --fix (twice) then oxfmt
pnpm check   # oxlint --type-aware --type-check, then tsc -b tsconfig.build.json
```

Both must be clean — `pnpm check` at zero lines of output. `build` is part of `check`, so a
separate `pnpm build` is only for when you want the artifacts.

`pnpm fix` runs the fixer twice on purpose: one pass does not converge on
`consistent-type-imports`, and the fixer emits import lists that are not formatted, so `oxfmt`
runs last.

`oxlint --type-check` is not the whole typecheck. It does not run declaration-emit diagnostics
(TS4025, TS2742), which are exactly the ones a library ships broken `.d.ts` files over. That is
why `pnpm check` ends in `tsc -b tsconfig.build.json`.

## Tests

```sh
pnpm test                      # vitest run --maxWorkers=2
npx vitest run <specific files> # while iterating
```

`--maxWorkers=2` is not a preference: the PGlite-backed suites time out against the 10s tripwire
when vitest runs at full concurrency.

## Toolchain versions

`typescript`, `@effect/tsgo`, `oxlint`, and `oxlint-tsgolint` are pinned exactly (no `^`) and move
in lockstep — `@effect/tsgo` patches the TypeScript and oxlint binaries in place, so a floating
range on any one of them silently unpatches the Effect rules. Bump all four together, and only to
a combination listed under "Supported Package Versions" in `node_modules/@effect/tsgo/README.md`.

`pnpm install` runs `scripts/prepare.mjs`, which applies the patch and installs the git hooks —
and exits 0 without doing either when the install is a consumer's rather than this repo's (it
keys on `INIT_CWD`, which package managers set; to run it by hand use `pnpm run prepare`, or
`INIT_CWD=$PWD node scripts/prepare.mjs`).
`npx effect-tsgo unpatch` restores the original binaries if you need an unpatched toolchain.

## Formatting

`oxfmt` must keep ignoring `**/__snapshots__/**` (`.oxfmtrc.json`). The OpenAPI snapshot is
compared byte for byte; reformatting it fails the suite.

## Casts and suppressions

The only `as unknown as` allowed anywhere in `src/` are the five sanctioned boundary casts
enumerated in REFACTOR.md §5, each justified in-code at its site. No new one without an amendment
there.

Every lint suppression is a single `// oxlint-disable-next-line <rule> -- <reason>` on the line it
applies to. No blanket or file-level disables, and no suppression without the reason.
