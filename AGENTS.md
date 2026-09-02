# effect-auth — how we work

Read this first. Then: `SPEC.md` is the authority on what the library is (its Amendments are the
decision log), `REFACTOR.md` holds the standing structural conventions, `README.md` is the user
tour. This file does not restate them; it tells you how to think and what to run.

## What this is

An Effect-native authentication library for Effect v4: sessions with a recorded assurance level,
email/password, OAuth/OIDC across fourteen providers, and seven plugins — e-mail codes, passkeys,
TOTP, phone, username, anonymous visitors, One Tap. Policy hooks, step-up, a cookie cache, a typed
client per plugin and a shipped test harness. Runs on PostgreSQL, SQLite and MySQL, and the whole
suite runs on each of them in CI (see SPEC Amendment 21). Inspired by
better-auth's semantics; shares none of its code. Pinned to `effect@4.0.0-rc.112` and built on its
`unstable/` namespace, so an `effect` bump is a deliberate event, never a drive-by.

Unpublished, `0.x`. There is no backward compatibility to keep. Break freely; record it in
`CHANGELOG.md`.

## Ethos — in priority order

1. **Correctness and safety.** Tokens hashed at rest. Time from `Clock`, randomness from
   `effect/Crypto`, never the globals. Closed core tables. Least surface. When a shortcut and a
   safe design disagree, the safe design wins without a discussion.
2. **Developer experience.** A call site should read like what it does. If an abstraction, an
   overload, or a rule makes call sites uglier without making them safer, delete it — Amendment 18
   is the precedent, and we will do it again.
3. **Elegance.** One way to do each thing. Small modules with one job. Nothing clever that a
   comment has to apologise for.

Everything is Effect-native and composes: services are `Context.Service` keys, failures are
`Schema.TaggedError`s, configuration is a Layer, boundaries are Schemas. If it does not compose,
it is not done.

Lean on the type system. The compiler proves; runtime checks are for the wire. A cast is a design
smell: exactly five boundary casts exist (`REFACTOR.md` §5), each at a place where effect's own
API types cannot be named, and there is no sixth. No `any` in a type position in `src/`.

No hacks, no drive-by suppressions. Every `oxlint-disable-next-line` carries a one-line reason
after `--`; there are a handful in the tree and the reviewer reads the list.

## Architecture

Three entry points: `effect-auth` (server), `effect-auth/client`, `effect-auth/testing` — plus
`effect-auth/passkeys` and `effect-auth/testing/{sqlite,postgres,mysql}`, each behind an optional
peer dependency.

| Directory | Owns |
|---|---|
| `src/config/` | `Auth.layer` / `Auth.layerWithOAuth` — the two static entry points; `AuthConfig`; e-mail composition |
| `src/domain/` | `Users`, `Sessions`, `Passwords`, `Accounts`, `Verifications`, `Challenges`, `SignIn`; `Assurance` (aal, methods, policies); the `Hooks`, `Authenticators` and `SignInPipeline` seams; the `Stores` interfaces; `Events`; `Schema` (the typed-view kernel for custom user fields) |
| `src/sql/` | `Migrations`; `Dialect.ts` (the four things pg/sqlite/mysql disagree about — the boolean codec, the lock clause, `columnType` over the column roles, `identifier`) and `Mutations.ts` (the six helpers that give MySQL an answer for `RETURNING`) |
| `src/sql/stores/` | One module per store — `Users`, `Sessions`, `Accounts`, `Verifications`, `Transaction`, and `internal.ts` for what two of them share. `SqlStores.ts` is the facade over them and the only public surface |
| `src/http/` | The `HttpApi` group, `Handlers`, `Middleware` (+`Live`), `Cookies`, `OriginCheck`, `RateLimits`, `SessionCache` |
| `src/oauth/` | `Flow`, `Provider`, `State`, `IdToken`, `Discovery`; `providers/` are plain values (fourteen of them) |
| `src/email-otp/` | The reference plugin — copy its shape for the next one. A code and a link over one row |
| `src/username/` | A lookup key over the password credential |
| `src/anonymous/` | A real `users` row at `aal0`, and the two halves of conversion |
| `src/passkeys/` | WebAuthn, on the `effect-auth/passkeys` subpath (it has a peer dependency) |
| `src/two-factor/` | TOTP, recovery codes, trusted devices — and the `SignInPipeline` decider |
| `src/phone/` | SMS codes, with the toll-fraud limits that go with them |
| `src/one-tap/` | Google One Tap over the existing id-token verifier |
| `src/crypto/` | `PasswordHasher`, `Token`, `Hmac`, `Totp`, `AuthCipher` |
| `src/client/` | The `AtomHttpApi` clients — `AuthClient`, one per plugin, and the `AuthAtoms` wrappers they share |
| `src/Plugin.ts` | `withDefaults`: the options-section resolver every plugin uses |
| `src/testing/` | The shipped harness (`AuthTest`, `MockProvider`, `TestHttpClient`, one `*Test` per plugin) and `Database.ts` — the `Provider` seam and `TestDatabase` — public API, treat it as such |
| `src/testing/{sqlite,postgres,mysql}/` | The three database providers, on subpaths behind optional peer dependencies. `effect-auth/testing` reaches them with the tree's only dynamic `import()`s and never statically |
| `src/internal/` | Not exported; helpers with no opinion |

Layering: `domain` never imports `http`; `http` never touches SQL; `oauth` owns flow policy and
its helpers own mechanics. A plugin is seams, not a registry: an `HttpApiGroup`, a Layer, its own
migrations from `0001`, a client, and the `AuthHooks` / `SignInPipeline` / `Authenticators` /
`Verifications` primitives — never a column on a core table.

One sign-in door: every session this library mints goes through `SignIn.complete`, which runs
`beforeSessionCreate`, consults the `SignInPipeline` (where a second factor interposes), mints, and
publishes `SignedIn`. `SessionsService.createUnchecked` is the raw mint and is named so you notice;
`test/domain/ChokePoint.test.ts` asserts `src/` calls it in exactly one place.

## Conventions that are not obvious from the code

- **Interface split.** Every service is `interface XService { … }` plus `class X extends
  Context.Service<X, XService>()("effect-auth/<module path>/<X>")`. The class is a pure key.
- **Keys are hand-maintained.** The `effect-auth/<module path>/<Identifier>` scheme is a
  convention, not a lint rule. The typed-view `*Of(model)` helpers restate the same literal — rename
  them in lockstep or you have silently created a second, unprovided service.
- **Errors.** Identifier `effect-auth/<Name>` (derives OpenAPI component names); `_tag` is the
  wire value. Both are fixed; `X.make({...})` to construct; `return yield* X.make()` to fail.
- **Values, not thunks.** `Accounts.make` is an `Effect`, `Accounts.layer` a `Layer`. Data-first
  signatures only; no `dual` unless the first argument is a real pipeable subject.
- **Provide once, at the edge.** Library code never calls `Effect.provide`. Tests are entry
  points and may.
- **Two entry points, no conditional types** in any exported signature, exactly one `ReturnType`
  (`AuthApiGroupOf`). Value-dependent layer types were removed on purpose; do not reintroduce them.
- **Tests** are `@effect/vitest` `layer()` blocks over a `Database.Provider`, `AuthTest.freshClock`
  for anything that moves time, `uniqueEmail` fixtures. The OpenAPI snapshot is byte-compared. A test
  asks `Database.TestDatabase` for table, column and index names — `information_schema`, `pg_catalog`
  and `PRAGMA` live in `src/testing/internal/catalog.ts` and nowhere else, which is what lets one
  assertion be true on all four backends.
- `@since` / `@category` on every export. Behaviour changes go in SPEC's Amendments; API changes in
  `CHANGELOG.md`.

## Working here

```sh
pnpm fix         # oxlint --fix twice, then oxfmt (one pass does not converge)
pnpm check       # oxlint --type-aware --type-check && tsc -b   — must print zero lines
pnpm test        # vitest run --maxWorkers=4, on PGlite
pnpm test:sqlite # the same suite on node:sqlite
pnpm test:pg     # …on PostgreSQL      ┐ Testcontainers, or EFFECT_AUTH_TEST_{POSTGRES,MYSQL}_URL.
pnpm test:mysql  # …on MySQL           ┘ `TESTCONTAINERS_REUSE_ENABLE=true` keeps the container.
```

- `check` includes the build. `oxlint --type-check` alone misses declaration-emit errors
  (TS4025/TS2742); that is why `tsc -b` is in there.
- A warn-level finding is a finding. Zero lines means zero lines.
- `typescript`, `@effect/tsgo`, `oxlint`, `oxlint-tsgolint` are pinned exactly and move together;
  `@effect/tsgo` patches the other three's binaries and hard-fails install on any other combination
  (see its README, "Supported Package Versions"). `pnpm run prepare` re-applies the patch and
  installs the lefthook pre-commit; it no-ops for consumers. `npx effect-tsgo unpatch` restores.
- `oxfmt` must keep ignoring `**/__snapshots__/**`.
- **Module isolation is off** (`isolate: false` in `vitest.config.ts`). Every file in a worker shares
  one module registry: measured on this tree, 1482 tests on PGlite went 32.3 s isolated → 20.2 s, at
  four workers. A change that needs isolation back has to say what state it leaks.
- **A module-level memo in `src/testing/` is legitimate, and only there.** With isolation off it is
  per worker rather than per file, which is exactly the lifetime a Testcontainers server and its
  admin pool want — one engine per worker, one database per build. It is test infrastructure, it is
  keyed by configuration, and its scope is deliberately never closed so a reused container survives
  the run. Nothing in `src/` outside `src/testing/` may hold module-level state.
- **Speed rules**, part of the definition of done for anything that touches tests: isolation stays
  off; one engine per worker and one schema or database per build (a provider that boots per build is
  unfinished); no new top-level `layer()` block where a nested `it.effect` would inherit the database
  — a case that needs an empty table calls `TestDatabase.reset`; service containers in CI, reusable
  containers locally. Every wave gate records wall time per dialect.
- The lint config runs stricter than Effect's `recommended` preset on purpose. Before turning a
  rule off, show the ergonomic damage it does in this tree (SPEC Amendment 18 is the template);
  before turning one on, show what it catches.

Definition of done for any change: `REFACTOR.md` §6. In short — gates green, suppression list
unchanged or justified, no new cast, SPEC amended if behaviour moved, CHANGELOG if the API did.

## Process

- Large or many-file changes run as a workflow: builders on **disjoint file buckets**, independent
  reviewers, a fix pass by hand. Never message a running workflow agent; stop it and finish by hand.
- A refactor that claims "no behaviour change" proves it: full suite, `.d.ts` diff against a build
  of the previous tree, snapshot byte-compare, and a reviewer told to refute the claim.
- Reference checkouts for API truth: `~/Documents/code/effect` (v4 monorepo) and
  `~/Documents/code/better-auth` (semantics only — never copy code).
- Design docs live beside this file: `hooks.md`, `roadmap.md`, `db-expansion.md` and its execution
  contract `db-expansion-plan.md`. Deferred work is in `roadmap.md`, not in code comments.
