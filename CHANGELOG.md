# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Nothing has been published to a registry yet, so there is exactly one section: everything below is
unreleased and will fold into the first tag. Nothing here is a breaking change *to a consumer*,
because there are no consumers — the entries are recorded so the first release notes can be written
from something other than a diff.

## [Unreleased]

### Changed

- **`Accounts.make` and `OAuthFlow.make` are Effect values, not thunks.** Both were
  `() => Effect.Effect<…>`; both are now `Effect.Effect<…>` declared directly. Call sites drop the
  parentheses:

  ```diff
  - const accounts = yield* Accounts.make()
  + const accounts = yield* Accounts.make
  ```

  These two were the only zero-argument `make` thunks in the package; every other `make` takes
  arguments and is unaffected.

- **`AnyUserModel.makeInsert` is a readonly property, not a method.** It was declared
  `makeInsert(input: UserInsertInput): Effect.Effect<UserInsertOf<{}>>` and is now
  `readonly makeInsert: (input: UserInsertInput) => Effect.Effect<UserInsertOf<{}>>`. Same shape at
  every call site; stricter for anyone *implementing* `AnyUserModel` by hand, because a property
  type is checked contravariantly in its parameter where a method signature is checked
  bivariantly. `UserModel<F>` and `UserModelInternal` already declared it as a property — this makes
  the three agree.

- **Every `Context.Service` key is module-qualified.** The scheme is
  `"effect-auth/<module path>/<Identifier>"`, with `<Identifier>` elided when it would only repeat
  the file name — so `"effect-auth/Sessions"` became `"effect-auth/domain/Sessions"`, and
  `"effect-auth/Token"` became `"effect-auth/crypto/Token"`. 25 keys in `src/` were renamed (all 26
  are now module-qualified; `"effect-auth/testing/TestEmails"` already was), plus 3 test-local ones. SPEC.md Amendment 17 has the full convention and its two consequences; the short
  version is that these keys are process-local context slots and are never serialized, so no wire
  format moved. Tagged-error `_tag`s, which *are* wire values, are untouched.

  Three `Context.Reference` keys are deliberately still unqualified:
  `"effect-auth/AuthoritativeSession"`, `"effect-auth/AuthHooks"` and `"effect-auth/UserModel"`.

- **`AuthConfigService.trustedOriginSet` is required.** `readonly trustedOriginSet:
  ReadonlySet<string>` is a non-optional field on the config service, built once by
  `AuthConfig.make` from `baseUrl` and `trustedOrigins` rather than recomputed per request. Anyone
  hand-constructing an `AuthConfigService` must now supply it; `OriginCheck.trustedOriginSet` is the
  exported function that builds one. (SPEC.md §14.)

- **`MockProvider.makeIdTokenSigner` remains a function**, `(): Effect.Effect<IdTokenSignerService>`.
  It is called as `yield* MockProvider.makeIdTokenSigner()`. Noted only because the surrounding
  `make` values above moved the other way and it deliberately did not: it mints a *fresh* key pair
  per call, which is what the forgery test needs, and a plain Effect value would read as though it
  did not.

### Added

- **Toolchain: TypeScript 7 (tsgo), `@effect/tsgo`, oxlint and oxfmt.** `pnpm check` is
  `oxlint --type-aware --type-check` followed by `tsc -b tsconfig.build.json`; `pnpm fix` is two
  oxlint fix passes then `oxfmt .`. `scripts/prepare.mjs` patches the TypeScript and oxlint binaries
  and installs lefthook's pre-commit hook, in this repo only. The four packages are pinned exactly
  and move in lockstep. See the README's Toolchain section.
- **`.oxlintrc.json` enumerates all 96 `@effect/tsgo` rules explicitly**, each severity carrying its
  reason inline. 90 at error, 4 at warn, 2 off (plus `typescript/consistent-return` off from the core
  set), with a `test/**` + `src/testing/**` override. SPEC.md
  Amendment 18 records what was dialed back and why.
- **CI** (`.github/workflows/ci.yml`): `pnpm check`, `pnpm format:check`, `pnpm test` on Node 20 and
  22.

### Removed

- **69 `dual()` data-last overloads in `src/`.** They were added to satisfy
  `effecttsgo/missing-pipeable-signature`; no caller in the library, its tests or `examples/basic`
  ever used one. Fifteen of them dispatched on a runtime predicate rather than arity, including
  `AuthHandlers.layer`. `grep -rn "dual(" src test` is now empty. The rule is off; see Amendment 18.
