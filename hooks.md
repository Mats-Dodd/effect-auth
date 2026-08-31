# Hooks: typed policy points for effect-auth

Status: planned, not built. Prerequisite for the next plugin wave (email OTP, TOTP, passkeys).

## Why

Consumers and plugins need to veto or enrich core operations — "reject sign-up from this
domain", "set `role` from the OAuth profile", "create a tenant row atomically with the user" —
and today the only answer is decorating a service with `Layer.provideMerge`, which is
whack-a-mole (users are created in three places) and only affects consumers above the
decorator. better-auth answers this with request-level `hooks.before/after` plus CRUD-shaped
`databaseHooks` on every model; both are the wrong altitude here. We add a small set of
**semantic** hook points consulted by core at defined moments, as an ordinary Effect service
with a no-op default.

Non-goals: request-level hooks (`HttpApiMiddleware` already does that), generic before/after
on store methods (store decorator seams like `Extras.sessionStore` do that), an `update` hook
(add `beforeUserUpdate` the day something needs it), after-commit side effects (`Auth.events`
does that, and stays fire-and-forget).

## Design

### The service — `src/domain/Hooks.ts` (new)

```ts
/** Where the person came from. OAuth carries the verified profile so one hook covers every provider. */
export type ProvisionSource =
  | { readonly _tag: "EmailPassword" }
  | { readonly _tag: "OAuth"; readonly providerId: string; readonly info: OAuthUserInfo }
  | { readonly _tag: "MagicLink" }
  | { readonly _tag: "Plugin"; readonly plugin: string }   // future plugins name themselves

export class PolicyRefused extends Schema.TaggedError<PolicyRefused>("effect-auth/PolicyRefused")(
  "PolicyRefused",
  { code: Schema.String, detail: Schema.optional(Schema.String) },
  { description: "A deployment policy refused the operation", httpApiStatus: 403 }
) {}

/** Every member optional; absent = allow unchanged. All run INSIDE the enclosing transaction. */
export interface AuthHooksService {
  /** May rewrite the candidate (custom fields included) or refuse. One choke point for every source. */
  readonly beforeUserCreate?: (options: {
    readonly candidate: UserInsertOf<{}>
    readonly source: ProvisionSource
  }) => Effect.Effect<UserInsertOf<{}>, PolicyRefused>
  /** Runs after the row exists, same transaction — the place for FK'd related rows (tenant, membership). */
  readonly afterUserCreate?: (options: {
    readonly user: UserOf<{}>
    readonly source: ProvisionSource
  }) => Effect.Effect<void, PolicyRefused>
  /** Veto sign-in / session minting for a user the store already knows (banned, suspended). */
  readonly beforeSessionCreate?: (options: {
    readonly user: UserOf<{}>
    readonly source: ProvisionSource
  }) => Effect.Effect<void, PolicyRefused>
  readonly beforeEmailChange?: (o: { user: UserOf<{}>; newEmail: string }) => Effect.Effect<void, PolicyRefused>
  readonly beforeUserDelete?: (o: { user: UserOf<{}> }) => Effect.Effect<void, PolicyRefused>
  readonly beforeAccountLink?: (o: {
    readonly user: UserOf<{}>
    readonly providerId: string
    readonly info: OAuthUserInfo
  }) => Effect.Effect<void, PolicyRefused>
}

/** Context.Reference: default = every hook absent, so Auth.layer needs nothing. */
export const AuthHooks = Context.Reference<AuthHooksService>("effect-auth/AuthHooks", { defaultValue: () => ({}) })

/** Monoid: before* chain left-to-right (each sees the previous rewrite; first refusal wins); after*/veto* sequence. */
export const combine: (first: AuthHooksService, second: AuthHooksService) => AuthHooksService
export const layer: (hooks: AuthHooksService) => Layer.Layer<never>          // Layer.succeed(AuthHooks)(hooks)
/** How a PLUGIN installs hooks without shadowing the consumer's: append, never replace. */
export const append: (hooks: AuthHooksService) => Layer.Layer<never>         // Layer.updateService(AuthHooks, (h) => combine(h, hooks))
/** Typed view for deployments with custom fields — same key string, candidate/user typed by the model. */
export const hooksOf: <F extends UserFields>(model: UserModel<F>) => Context.Reference<AuthHooksOf<F>>
```

Verified against rc.112: `Context.Reference(key, { defaultValue })` (Context.d.ts:1643),
`Layer.updateService` (Layer.d.ts:3250). Implementation must confirm `Layer.updateService`
applies over a Reference's default when nothing provided it; if it does not, `append` reads
the current value with `Effect.service(AuthHooks)` inside `Layer.effectDiscard`-style wiring —
resolve at the first test, not by widening the design.

### The choke point — `Users.provision`

The three user-creation sites (`src/domain/Passwords.ts:579`, `src/domain/Accounts.ts:310`,
`src/magic-link/MagicLink.ts:581`) each do `insertRow(UserModel.insert, {...})` then
`users.create(row)`. Lift that into one domain function all three call:

```ts
// UsersService gains:
readonly provision: (options: {
  readonly candidate: UserInsertOf<F>          // already carries the app-generated UUIDv7 id
  readonly source: ProvisionSource
}) => Effect.Effect<UserOf<F>, PolicyRefused | PersistenceError>
// = hooks.beforeUserCreate (rewrite|refuse) -> userStore.create -> hooks.afterUserCreate
```

`provision` does NOT publish `UserCreated` — emission stays with the callers, after commit,
as today (Events.ts discipline). It does NOT open a transaction — it runs inside whichever
transaction the caller holds, so a refusal or a failed `afterUserCreate` aborts the whole
sign-up atomically. Rewrites are re-validated: the rewritten candidate goes back through
`insertRow(model.insert, …)` so a hook cannot smuggle an invalid row past the schema.

Session vetoes: `Sessions.create` stays hook-free (it is also used by tests/plumbing);
`beforeSessionCreate` is called by the four sign-in paths right before their
`sessions.create` (`Passwords.ts:609` sign-up auto-session, `Passwords.ts:652` sign-in,
`oauth/Flow.ts:897`, `magic-link/MagicLink.ts:708`). Ordering: AFTER credential verification
(the dummy-hash timing defence must not be skipped), so a refusal reveals nothing a correct
password would not already reveal.

`beforeEmailChange` runs in `Users.requestEmailChange` before any token is minted (both the
verified and unverified branches, before the taken/free fork so the enumeration posture is
unchanged). `beforeUserDelete` runs in `Users.requestDeletion` after the freshness check and
in `confirmDeletion` after the claim (claim-first stays: a refused link is still burnt).
`beforeAccountLink` runs in `Accounts.linkOAuth` before an account row is attached to an
EXISTING user (implicit linking and `linkSocial` both), not on first provision — that is
`beforeUserCreate`'s job.

### Error surface

`PolicyRefused` (403) is added to the error arrays of: `signUpEmail`, `signInEmail`,
`signInSocial`, `linkSocial`, `changeEmail`, `deleteUser`, magic-link `exchange`. The
redirect-shaped completions (`oauthCallback`, magic-link `verify`, `deleteUserCallback`)
encode it as `?error=policy_refused&code=<hook code>` via the existing `withErrorCode`
(`src/http/OriginCheck.ts:236`) — same pattern as `invalid_token`. `code` is
deployment-authored and shown to callers: hooks must not put secrets in it (JSDoc rule).
Handlers do NOT `serverFault` it — it is a caller error. Client entries pick the new error
member up from the endpoint types; `test/client/stub.ts` routes unchanged.

### Consumer / plugin usage (goes in README)

```ts
const Hooks = AuthHooks.layer({
  beforeUserCreate: ({ candidate, source }) =>
    candidate.email.endsWith("@acme.com")
      ? Effect.succeed(candidate)
      : Effect.fail(new PolicyRefused({ code: "domain_not_allowed" })),
  afterUserCreate: ({ user }) => Memberships.create({ userId: user.id })   // same transaction
})
const AuthLive = Auth.layer(opts).pipe(Layer.provide(Hooks), Layer.provide(PgLive), ...)
// a plugin, never knowing what else is installed:
const PluginHooks = AuthHooks.append({ beforeSessionCreate: ... })
```

Rules to document: hooks are short and local — they hold the sign-up transaction open, so no
network calls (use `Auth.events` for side effects); `PolicyRefused` is the only typed failure
(anything thrown is a defect and 500s, correctly); a ban enforced by `beforeSessionCreate`
does not touch live sessions — pair it with `cookieCache.version` keyed on a PUBLIC field
(never a hidden one, per AuthConfig docs) or revocation.

## Files touched

- new `src/domain/Hooks.ts` (+ export in `src/index.ts`, SPEC amendment, README section)
- `src/domain/Users.ts` — `provision`, `beforeEmailChange`, `beforeUserDelete` call sites
- `src/domain/Passwords.ts`, `src/domain/Accounts.ts`, `src/magic-link/MagicLink.ts` — onto
  `Users.provision`; `beforeSessionCreate` at the four sign-in sites; `beforeAccountLink`
- `src/oauth/Flow.ts` — `beforeSessionCreate` + `policy_refused` redirect outcome
- `src/http/AuthApi.ts` + `Handlers.ts` + `src/magic-link/{Api,Handlers}.ts` — error arrays,
  redirect encodings
- `src/domain/Errors.ts` — `PolicyRefused` into `AuthError`
- `src/client/AuthClient.ts` / `MagicLinkClient.ts` — error-type lines only
- `src/testing/TestLayer.ts` — `Options.hooks?: AuthHooksService` convenience seam

Error channels: `UsersService`/`PasswordsService`/`AccountsService`/`OAuthFlowService`/
`MagicLinkService` methods that can now refuse gain `PolicyRefused` in their unions — a
breaking-change surface; SPEC records it. No migrations, no new tables, no config.

## Tests (patterns per the existing suite: layer() blocks, uniqueEmail, freshClock)

- `test/domain/Hooks.test.ts`: veto + rewrite + atomic-after across all three provision
  sources (password, OAuth via `AuthTest.layerFlow` + MockProvider, magic link via
  `MagicLinkTest.layer`); a failing `afterUserCreate` leaves NO user row (transaction
  aborts); rewrite is schema-re-validated (a hook returning `emailVerified: true` on a
  GeneratedByApp-style field is refused/overwritten per the model); `combine` ordering and
  first-refusal-wins; `append` on top of a consumer `layer`; default = everything allowed
  (one smoke assertion — the other 657 tests already prove it).
- `beforeSessionCreate`: banned user → password sign-in fails `PolicyRefused` with
  `countingHasher` proving the verify still ran once (timing defence intact); OAuth callback
  and magic-link verify redirect with `?error=policy_refused&code=...`; sign-up auto-session
  refused → decide and pin: sign-up SUCCEEDS with `session: null` (user exists, cannot start
  a session) — matches `SignUpResponse`'s nullable session.
- `beforeEmailChange` / `beforeUserDelete` / `beforeAccountLink`: one veto test each at the
  HTTP layer; `deleteUserCallback` refusal burns the token.
- `test/fields/`: `hooksOf(model)` — a hook reads and rewrites `plan`, typed (`*.types.ts`
  line: candidate is `UserInsertOf<F>`; base-typed hooks still assignable).
- Type tests: `Auth.layer` return type unchanged; `PolicyRefused` appears in the client's
  sign-in error union.

## Execution

Small wave, same discipline as before: 2 Opus builders (1: Hooks.ts + provision refactor +
domain call sites + domain tests; 2: HTTP/error surface + clients + HTTP/fields tests + SPEC/
README) sequenced 1→2, then 1 Fable review (security lens: timing defences, enumeration
posture unchanged, transaction atomicity, hook-code leakage) + fix pass. Gates as always:
`pnpm check/build/test` green, count only grows from 657, cast gate unchanged (no new casts —
`hooksOf` reuses the typed-view pattern; if it needs a cast, it joins REFACTOR §5 with the
same justification as `currentUserOf`), two shuffled seeds.
