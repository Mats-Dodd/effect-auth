# effect-auth — how we work

Read this first. Then: `SPEC.md` is the authority on what the library is (its Amendments are the
decision log), `REFACTOR.md` holds the standing structural conventions, `README.md` is the user
tour. This file does not restate them; it tells you how to think and what to run.

## What this is

An Effect-native authentication library for Effect v4: sessions, email/password, OAuth/OIDC,
magic link, policy hooks, a cookie cache, a typed client and a shipped test harness. Inspired by
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

Three entry points: `effect-auth` (server), `effect-auth/client`, `effect-auth/testing`.

| Directory | Owns |
|---|---|
| `src/config/` | `Auth.layer` / `Auth.layerWithOAuth` — the two static entry points; `AuthConfig`; e-mail composition |
| `src/domain/` | `Users`, `Sessions`, `Passwords`, `Accounts`, `Verifications`; the four `Stores` interfaces; `Events`; `Hooks`; `Schema` (the typed-view kernel for custom user fields) |
| `src/sql/` | The four stores over `@effect/sql`; `Migrations` |
| `src/http/` | The `HttpApi` group, `Handlers`, `Middleware` (+`Live`), `Cookies`, `OriginCheck`, `RateLimits`, `SessionCache` |
| `src/oauth/` | `Flow`, `Provider`, `State`, `IdToken`, `Discovery`; `providers/` are plain values |
| `src/magic-link/` | The reference plugin — copy its shape for the next one |
| `src/crypto/` | `PasswordHasher`, `Token`, `Hmac` |
| `src/client/` | The `AtomHttpApi` client |
| `src/testing/` | The shipped harness (`AuthTest`, `MockProvider`, `TestHttpClient`) — public API, treat it as such |
| `src/internal/` | Not exported; helpers with no opinion |

Layering: `domain` never imports `http`; `http` never touches SQL; `oauth` owns flow policy and
its helpers own mechanics. A plugin is seams, not a registry: an `HttpApiGroup`, a Layer, a
migrations record, a client function, and the `AuthHooks` / `Verifications` primitives — never a
column on a core table.

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
- **Tests** are `@effect/vitest` `layer()` blocks, one PGlite per file, `AuthTest.freshClock` for
  anything that moves time, `uniqueEmail` fixtures. The OpenAPI snapshot is byte-compared.
- `@since` / `@category` on every export. Behaviour changes go in SPEC's Amendments; API changes in
  `CHANGELOG.md`.

## Working here

```sh
pnpm fix      # oxlint --fix twice, then oxfmt (one pass does not converge)
pnpm check    # oxlint --type-aware --type-check && tsc -b   — must print zero lines
pnpm test     # vitest --maxWorkers=2 (PGlite suites flake at full concurrency)
```

- `check` includes the build. `oxlint --type-check` alone misses declaration-emit errors
  (TS4025/TS2742); that is why `tsc -b` is in there.
- A warn-level finding is a finding. Zero lines means zero lines.
- `typescript`, `@effect/tsgo`, `oxlint`, `oxlint-tsgolint` are pinned exactly and move together;
  `@effect/tsgo` patches the other three's binaries and hard-fails install on any other combination
  (see its README, "Supported Package Versions"). `pnpm run prepare` re-applies the patch and
  installs the lefthook pre-commit; it no-ops for consumers. `npx effect-tsgo unpatch` restores.
- `oxfmt` must keep ignoring `**/__snapshots__/**`.
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
- Design docs live beside this file: `hooks.md`, `roadmap.md`, `db-expansion.md`. Deferred work is
  in `roadmap.md`, not in code comments.
