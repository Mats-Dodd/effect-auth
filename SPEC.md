# effect-auth v1 Specification

Ground truth for building `effect-auth`: an Effect-native authentication library, a ground-up
rewrite inspired by [better-auth](https://better-auth.com) (MIT), rebuilt on Effect v4 primitives.
Attribution to better-auth goes in the README.

**Scope: authentication only.** Sessions, email/password, OAuth. No authorization (roles,
permissions, policies) in core — but `CurrentSession`/`CurrentUser` must carry a clean principal
shape so a future policy middleware (e.g. Cedar-backed) can `require` them without core changes.
No RPC transport — the domain layer stays transport-neutral so it remains possible later.

## Reference checkouts (read these, do not modify them)

- `/Users/matthewdodd/Documents/code/effect` — the Effect v4 monorepo (4.0.0-rc). Study API shapes here.
- `/Users/matthewdodd/Documents/code/better-auth` — better-auth. Study flows/semantics here. Never copy code.

Key reference files:

| Topic | File |
|---|---|
| Security middleware declaration | `effect/ai-docs/src/51_http-server/fixtures/api/Authorization.ts` |
| Security middleware implementation | `effect/ai-docs/src/51_http-server/fixtures/server/Authorization.ts` |
| HttpApi group/endpoint tour | `effect/ai-docs/src/51_http-server/fixtures/api/Users.ts` |
| Model example | `effect/ai-docs/src/51_http-server/fixtures/domain/User.ts` |
| Middleware types | `effect/packages/effect/src/unstable/httpapi/HttpApiMiddleware.ts` |
| securityDecode / securitySetCookie | `effect/packages/effect/src/unstable/httpapi/HttpApiBuilder.ts` (:475, :541) |
| Service-library idiom (sections, layer/layerConfig) | `effect/packages/ai/anthropic/src/AnthropicClient.ts` |
| WebCrypto-behind-a-service pattern | `effect/packages/effect/src/unstable/eventlog/EventLogEncryption.ts` (:102) |
| Model.Class field helpers | `effect/packages/effect/src/unstable/schema/Model.ts` |
| Repository helper | `effect/packages/effect/src/unstable/sql/SqlModel.ts` (:33) |
| Migrator.fromRecord | `effect/packages/effect/src/unstable/sql/Migrator.ts` (:384) |
| Rate limiter | `effect/packages/effect/src/unstable/persistence/RateLimiter.ts` |
| AtomHttpApi | `effect/packages/effect/src/unstable/reactivity/AtomHttpApi.ts` |
| HttpApiError built-ins | `effect/packages/effect/src/unstable/httpapi/HttpApiError.ts` |
| Cookies | `effect/packages/effect/src/unstable/http/Cookies.ts` |
| Redacted header names | `effect/packages/effect/src/unstable/http/Headers.ts` (`CurrentRedactedNames`) |
| Coding patterns (MUST follow) | `effect/.patterns/effect.md`, `effect/.patterns/testing.md`, `effect/.patterns/dynamic-records.md` |
| better-auth session semantics | `better-auth/packages/better-auth/src/db/internal-adapter.ts`, `src/cookies/index.ts` |
| better-auth OAuth core | `better-auth/packages/core/src/oauth2/` |
| better-auth account linking | `better-auth/packages/better-auth/src/oauth2/link-account.ts` |
| better-auth tables | `better-auth/packages/core/src/db/get-tables.ts`, `src/db/schema/*.ts` |

## Package

Single package `effect-auth`, ESM only (`"type": "module"`, `sideEffects: []`).

- Runtime dependencies: **`jose@^6.2.10` only** (used ONLY under `src/oauth/` for OIDC id_token/JWKS verification).
- Peer dependency: `effect@4.0.0-rc.112` (exact pin in devDependencies; `peerDependencies: "4.0.0-rc.112"`).
- Dev dependencies: `@effect/vitest@4.0.0-rc.112`, `@effect/sql-pglite@4.0.0-rc.112`, `vitest`, `typescript@^5.7`, `@types/node`.
- Node >= 20. Package manager: pnpm.

Subpath exports:

```
"effect-auth"          -> src/index.ts        (domain + http + oauth + config)
"effect-auth/client"   -> src/client/index.ts (AtomHttpApi wrapper; browser-safe, no node imports)
"effect-auth/testing"  -> src/testing/index.ts
```

TypeScript config: strict, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`,
`erasableSyntaxOnly` (no enums, no parameter properties), `module: nodenext`,
`moduleResolution: nodenext`. Relative imports use explicit `.js` extensions
(NodeNext resolution over `.ts` sources compiled by tsc; follow whatever the scaffold
establishes and keep it consistent). Build = `tsc -b`. Test = vitest with `@effect/vitest`.

## Coding conventions (non-negotiable, from effect/.patterns)

- Services are `class X extends Context.Service<X, Shape>()("effect-auth/X") {}`. Import from `effect`.
  Check the v4 checkout for the exact `Context.Service` signature before writing.
- No try/catch inside `Effect.gen` — use `Effect.result` / typed errors.
- `return yield*` for terminal effects; prefer `Effect.fnUntraced(function* (...) {...})` over
  a function whose body is only `Effect.gen`.
- Errors are `Schema.TaggedError` classes (check v4 name — may be `Schema.ErrorClass`/`Data.TaggedError`;
  match what `HttpApiError.ts` and `RateLimiter.ts` do so errors drop into endpoint error unions).
- Secrets are `Redacted<string>` end to end; unwrap only at the last moment.
- Attacker-influenced record keys: owned dicts via `Object.create(null)`; check external records
  only with `Object.hasOwn`; never `in`, never `for...in`, spread (`{...x}`) not `Object.assign({}, x)`.
- Tests: `@effect/vitest`, `it.effect` (already scoped — never wrap in `Effect.scoped`), `assert` not
  `expect`, `TestClock` for time, never `Effect.runSync` in tests.
- JSDoc on public exports with `@since 1.0.0` and one `@category` (constructors|models|services|layers|errors|combinators|guards).

## Module map & ownership

```
src/
  crypto/       PasswordHasher.ts, Hmac.ts, Token.ts
  domain/       Schema.ts (Models), Errors.ts, Stores.ts (4 store services),
                Sessions.ts, Accounts.ts, Passwords.ts, Events.ts, Ids.ts
  sql/          SqlStores.ts (one layer implementing all 4 stores), Migrations.ts
  http/         AuthApi.ts (group + endpoint declarations), Middleware.ts (Authenticated, requireFresh),
                Handlers.ts (AuthHandlers.layer factory), Cookies.ts (config service), RateLimits.ts,
                OriginCheck.ts
  oauth/        Provider.ts (interface), Flow.ts (generic runner), State.ts,
                providers/Github.ts, providers/Google.ts, IdToken.ts (jose)
  config/       AuthConfig.ts, Auth.ts (the batteries `Auth.layer` / `Auth.layerConfig`)
  client/       AuthClient.ts
  testing/      TestLayer.ts (Auth.layerTest on pglite)
  index.ts      (barrel)
```

## Crypto (src/crypto)

All services over WebCrypto (`globalThis.crypto.subtle`) behind `Context.Service`, mockable.
Pattern: `EventLogEncryption.makeEncryptionSubtle`.

**PasswordHasher** service: `hash(password: Redacted<string>) => Effect<string, PasswordHashError>`,
`verify(password: Redacted<string>, hash: string) => Effect<boolean, PasswordHashError>`.

- Default layer `PasswordHasher.layerScrypt`: scrypt via `node:crypto` (`scrypt` promisified),
  params N=16384, r=16, p=1, dkLen=64, 16-byte random salt.
  Stored format: `scrypt$n=16384,r=16,p=1$<base64url salt>$<base64url key>` (self-describing for
  future migration; do NOT copy better-auth's bare `salt:hex` format).
- Portable layer `PasswordHasher.layerPbkdf2`: WebCrypto PBKDF2-HMAC-SHA512, 600_000 iterations,
  format `pbkdf2$i=600000$<salt>$<key>`. `verify` dispatches on the format prefix so either layer
  verifies both formats where the primitive is available.
- Constant-time comparison for digests (implement `timingSafeEqualUint8` manually over bytes; do
  not use string ===).

**Hmac** service: `sign(data: Uint8Array) => Effect<Uint8Array>`, `verify(data, mac) => Effect<boolean>`
using HMAC-SHA-256 via WebCrypto, keyed from `AuthConfig.secret`. (v1 uses it for origin-state
integrity where needed; the cookie cache that needs it heavily is v2.)

**Token.ts**: `generateToken` — 32 bytes from `effect/Crypto` `randomBytes`, base64url-encoded
(43 chars). `hashToken(token) => Effect<string>` — SHA-256, base64url. Sessions and verification
values are stored HASHED at rest; lookups compute the hash first.

Write the redaction/log test FIRST (see AnthropicClient.test.ts precedent): asserts a
`Redacted` password/token renders as `<redacted>` in logs and error output.

## Domain (src/domain)

### Models (Schema.ts) — via `unstable/schema/Model.ts` `Model.Class`

IDs: UUIDv7 strings generated app-side (`effect/Crypto.randomUUIDv7`) — sortable, index-friendly.
All models get `createdAt`/`updatedAt` via `DateTimeInsert`/`DateTimeUpdate`.

- **User**: `id`, `name: string`, `email: string` (unique, lowercased on write), `emailVerified: boolean`
  (never client-writable), `image: string | null`.
- **Session**: `id`, `tokenHash: string` (unique — SHA-256 of the opaque token; the raw token is
  NEVER stored), `userId` (FK user.id, cascade, indexed), `expiresAt: DateTime`,
  `ipAddress: string | null`, `userAgent: string | null`.
- **Account**: `id`, `issuer: string`, `accountId: string`, `providerId: string`, `userId` (FK,
  cascade, indexed), `accessToken/refreshToken/idToken: string | null` (Sensitive — excluded from
  JSON), `accessTokenExpiresAt/refreshTokenExpiresAt: DateTime | null`, `scope: string | null`,
  `passwordHash: string | null` (Sensitive). Compound unique `(issuer, accountId)`.
  Non-OAuth identities use synthetic issuers: `local:credential` for email/password
  (accountId = userId). OAuth issuer = the provider's OIDC issuer URL, or `local:oauth:<providerId>`
  for plain OAuth2 providers without one (GitHub).
- **Verification**: `id`, `identifier: string` (indexed; namespaced like `email-verify:<email>`,
  `password-reset:<userId>`, `oauth-state:<nonce>`), `valueHash: string`, `payload: string | null`
  (JSON for OAuth state), `expiresAt: DateTime`.

Public-facing schemas: session responses expose a `Session` WITHOUT tokenHash; `User` without
nothing extra (email included). Use Model variants (`.json`) to enforce.

### Errors (Errors.ts)

Tagged, Schema-encoded, granular — these ARE the client contract:
`InvalidCredentials`, `EmailNotVerified`, `UserAlreadyExists`, `UserNotFound`, `SessionExpired`,
`Unauthorized` (reuse/alias HttpApiError.Unauthorized where it fits), `SessionNotFresh`,
`InvalidToken` (verification), `TokenExpired`, `PasswordPolicyViolation` (min 8 / max 128 chars v1),
`OAuthStateMismatch`, `OAuthProviderError`, `AccountAlreadyLinked`, `CannotUnlinkLastAccount`,
`RateLimited` (reuse RateLimiter's `RateLimitExceeded` if it fits endpoint unions), `EmailDeliveryError`.
Each carries minimal safe fields (no secrets, no user enumeration data).

### Store services (Stores.ts) — the swappable persistence seam

Four `Context.Service`s. Domain logic depends ONLY on these; the SQL layer implements them.
Fail with `PersistenceError` (tagged wrapper) — never leak SqlError types upward.

- **UserStore**: `create`, `findById`, `findByEmail`, `update` (partial), `delete`.
- **SessionStore**: `create`, `findByTokenHash` (returns session WITH user — the one relational
  read), `touch(id, expiresAt)` (rolling refresh), `deleteById`, `deleteByUserId`,
  `deleteByUserIdExcept(userId, sessionId)`, `listByUserId` (non-expired).
- **AccountStore**: `create`, `findByIssuerAccountId`, `findByUserIdAndProviderId`, `listByUserId`,
  `updateTokens`, `deleteById`, `countByUserId`.
- **VerificationStore**: `create`, **`consume(identifier, valueHash) => Effect<Verification | null>`**
  — MUST be atomic single-use (SQL: `DELETE ... WHERE identifier = ? AND value_hash = ? AND
  expires_at > now RETURNING *`). This is the entire race-safety story for reset tokens, email
  verification, and OAuth state. Also `deleteExpired`.

`TransactionContext`: multi-store operations (e.g. OAuth sign-up = create user + account + session)
run inside `sql.withTransaction` at the domain layer via a small `withAuthTransaction` helper the
SQL layer provides (a `Context.Service` with `run: <A,E,R>(effect) => Effect<A,E,R>`; the test/
memory impl may be identity).

### Domain services

**Sessions** (Sessions.ts): the lifecycle brain. Config knobs (via AuthConfig):
`expiresIn` default 7 days, `updateAge` default 1 day (rolling refresh when
`expiresAt - expiresIn + updateAge <= now`), `freshAge` default 1 day.
- `create({userId, ipAddress?, userAgent?, rememberMe?})` -> `{ session, token }` (raw token
  returned exactly once; `rememberMe: false` -> 1 day expiry).
- `verify(token)` -> `{ session, user } | fails SessionExpired/Unauthorized`; performs rolling
  refresh transparently and reports `refreshed: boolean` so the HTTP layer can re-set the cookie.
- `revoke(sessionId, userId)`, `revokeAll(userId)`, `revokeOthers(userId, currentSessionId)`,
  `list(userId)`.
- `isFresh(session)` per freshAge.

**Passwords** (Passwords.ts): `signUp({email, password, name})` (creates user + `local:credential`
account in a transaction; emits UserCreated; triggers verification email when configured),
`signIn({email, password})` (timing-safe: ALWAYS run a hash verify even when the user is missing —
verify against a pre-computed dummy hash — to prevent user enumeration by timing),
`requestReset(email)` (silently succeeds when user unknown — no enumeration; token TTL 1h),
`resetPassword({token, newPassword})` (consumes token, updates hash, revokes all sessions),
`changePassword({userId, currentPassword, newPassword, revokeOtherSessions?})`,
`sendVerificationEmail(email)`, `verifyEmail(token)` (consume + set emailVerified).
Email verification requirement is config: `requireEmailVerification: boolean` (default false;
when true, signIn fails `EmailNotVerified` for unverified users).

**Accounts** (Accounts.ts): `linkOAuth` — the better-auth linking algorithm:
1. lookup by `(issuer, accountId)` -> existing account = sign-in (update tokens).
2. else if a user exists with the provider-reported email: implicit link ONLY when the provider
   email is verified AND (provider is in `trustedProviders` config OR the local user's
   emailVerified is true). Otherwise fail `AccountAlreadyLinked` guidance error.
3. else create user (emailVerified = provider's claim) + account.
Also `unlink` (refuse when it would leave zero sign-in methods: `CannotUnlinkLastAccount`),
`listForUser`.

**Events** (Events.ts): `AuthEvent` tagged union — `UserCreated`, `SignedIn` (method: "password" |
"oauth:<id>"), `SignedOut`, `SessionRevoked`, `PasswordChanged`, `PasswordResetRequested`,
`EmailVerified`, `AccountLinked`, `AccountUnlinked`. `AuthEvents` service over a `PubSub`;
`Auth.events: Stream<AuthEvent>`. Emission is after-commit (emit after the transaction effect
succeeds), best-effort (never fail the request on publish).

**AuthEmails** service (config/): user-implemented seam —
`sendVerification({user, token, url})`, `sendPasswordReset({user, token, url})`, both
`Effect<void, EmailDeliveryError>`. URLs built from `AuthConfig.baseUrl` + configurable paths.

## SQL layer (src/sql)

`SqlStores.layer: Layer<UserStore | SessionStore | AccountStore | VerificationStore |
WithAuthTransaction, never, SqlClient>` — one layer, tagged-template SQL + `SqlSchema.findOne/findAll`
decoding into the Models. Use `sql.onDialect` for pg/sqlite divergence. The session+user read is
ONE joined query (or two batched — measure nothing, just write the join).

**Migrations.ts**: a `Migrator.fromRecord`-compatible record (`0001_create_users`, `0002_...`)
covering both dialects via `sql.onDialect`. Export the record AND
`Migrations.layer` (runs the migrator — document as dev/quickstart convenience) so users can
either merge into their own Migrator or auto-run. Indexes: users.email unique; sessions.token_hash
unique, sessions.user_id; accounts (issuer, account_id) unique, accounts.user_id;
verifications.identifier.

## HTTP surface (src/http)

### Middleware (Middleware.ts)

```ts
class CurrentSession extends Context.Key<CurrentSession, Session>()("effect-auth/CurrentSession") {}
class CurrentUser extends Context.Key<CurrentUser, User>()("effect-auth/CurrentUser") {}
```
(check v4 idiom for plain context keys — `Context.Key`/`Context.Tag` — match the codebase.)

`Authenticated` — `HttpApiMiddleware.Service` with
`security: { session: HttpApiSecurity.apiKey({ key: <cookieName>, in: "cookie" }), bearer: HttpApiSecurity.bearer }`,
`provides: CurrentUser | CurrentSession` (check how multiple provides are expressed; if single,
provide CurrentSession and derive CurrentUser via a second middleware or a combined
`Authenticated` context object `{ user, session }` under one key — pick what typechecks cleanly
and document it), `error: Unauthorized`, `requiredForClient: true`.
Bearer accepts the same opaque session token (for non-browser clients).
Implementation layer verifies via `Sessions.verify`, re-sets the cookie on rolling refresh.

`requireFresh` — an `Effect` guard (`Effect<void, SessionNotFresh, CurrentSession>`) handlers call
for sensitive ops (change-password, unlink); simpler than a second middleware.

Cookie: name `effect_auth.session` (`__Secure-` prefix + `secure` when baseUrl is https),
httpOnly, sameSite=lax, path=/, maxAge = session expiry. Set via `HttpApiBuilder.securitySetCookie`
or response cookie APIs. Register the cookie/header names with `Headers.CurrentRedactedNames`.

### AuthApi (AuthApi.ts) — `HttpApiGroup.make("auth")`, all under `/auth` prefix

| Endpoint | Method/Path | Errors (beyond 500) |
|---|---|---|
| signUpEmail | POST /sign-up/email | UserAlreadyExists, PasswordPolicyViolation, RateLimited |
| signInEmail | POST /sign-in/email | InvalidCredentials, EmailNotVerified, RateLimited |
| signOut | POST /sign-out | Unauthorized |
| getSession | GET /session | Unauthorized |
| listSessions | GET /sessions | Unauthorized |
| revokeSession | POST /revoke-session | Unauthorized, NotFound |
| revokeSessions | POST /revoke-sessions | Unauthorized |
| revokeOtherSessions | POST /revoke-other-sessions | Unauthorized |
| requestPasswordReset | POST /request-password-reset | RateLimited (ALWAYS 200 otherwise — no enumeration) |
| resetPassword | POST /reset-password | InvalidToken, TokenExpired, PasswordPolicyViolation |
| changePassword | POST /change-password | Unauthorized, InvalidCredentials, SessionNotFresh, PasswordPolicyViolation |
| sendVerificationEmail | POST /send-verification-email | RateLimited (200 always otherwise) |
| verifyEmail | GET /verify-email?token= | InvalidToken, TokenExpired |
| signInSocial | POST /sign-in/social | OAuthProviderError |
| oauthCallback | GET /callback/:providerId | OAuthStateMismatch, OAuthProviderError |
| listAccounts | GET /accounts | Unauthorized |
| linkSocial | POST /link-social | Unauthorized, OAuthProviderError |
| unlinkAccount | POST /unlink-account | Unauthorized, CannotUnlinkLastAccount, NotFound |

Session-required endpoints get `.middleware(Authenticated)` per-endpoint (the group is mixed).
Success schemas: signIn/signUp -> `{ user, session }` (+ cookie set); getSession -> `{ user, session }`;
oauthCallback -> 302 redirect to validated callbackURL.

### Handlers (Handlers.ts)

`AuthHandlers.layer(api)` — factory taking the consumer's `HttpApi` so the group layer's ApiId
infers (a prebuilt layer cannot typecheck against an arbitrary consumer API). Thin: decode ->
call domain service -> map to response + cookies. No business logic in handlers.

### Cross-cutting

- **RateLimits.ts**: via `unstable/persistence` RateLimiter (memory store default): sign-in/sign-up
  3 per 10s per (ip, path); password-reset + send-verification 3 per 60s. No derivable client IP =>
  fall into a shared fail-closed bucket. IP from a configurable header chain
  (`x-forwarded-for` first hop) — document the trust caveat.
- **OriginCheck.ts**: for cookie-authenticated state-changing requests (POST with session cookie),
  verify `Origin`/`Referer` host is in `AuthConfig.trustedOrigins` (baseUrl origin is always
  trusted). Absent Origin on non-browser bearer requests: allowed. Applied inside the
  Authenticated implementation (cookie path only).
- **Open-redirect defense**: every user-supplied `callbackURL`/`redirectTo` must be relative, or
  absolute with origin in `trustedOrigins`; otherwise fall back to baseUrl.

## OAuth (src/oauth)

**Provider.ts** — the provider seam (declarative, most providers are just config):

```ts
interface OAuthProviderConfig {
  id: string
  clientId: string
  clientSecret: Redacted<string>
  authorizationUrl: string
  tokenUrl: string
  scopes: string[]
  issuer?: string                    // OIDC issuer; enables id_token path
  jwksUrl?: string
  userInfo: (tokens) => Effect<OAuthUserInfo, OAuthProviderError, HttpClient>
  accountId: (info) => string       // stable subject — NEVER email
}
```

**Flow.ts** — generic runner:
- start: mint state nonce (Token.generateToken) + PKCE verifier; store StateData
  (`callbackURL`, `codeVerifier`, `link?: {userId}`, `expiresAt` now+10min) as a Verification row
  (`identifier: oauth-state:<nonce>`, valueHash = hash(nonce), payload = JSON). Redirect with
  `state=<nonce>`, `code_challenge` S256 (ALWAYS — no plain fallback).
- callback: `VerificationStore.consume` the state (single-use, atomic), exchange code
  (client_secret_post; **the token/userinfo fetches must refuse redirects** — follow
  better-auth's `reject-redirects.ts` approach with effect's HttpClient), verify id_token when
  OIDC (jose `createRemoteJWKSet`, check iss/aud/exp/nonce; FAIL CLOSED on any missing piece),
  then `Accounts.linkOAuth`, create session, set cookie, 302 to validated callbackURL.
  On failure: redirect to `errorURL` (validated) with a safe error code query param — never leak
  provider errors verbatim.

**providers/Github.ts** — plain OAuth2: authorize/token endpoints, userinfo `GET /user` +
`GET /user/emails` (pick primary verified email; `email_verified` = that flag), accountId = `id`.
**providers/Google.ts** — OIDC: issuer `https://accounts.google.com`, id_token path, accountId =
`sub`, email_verified from claim.

Providers register via `OAuthProviders` service (a keyed record, `Object.create(null)`), each with
`Github.layer({...})` / `Github.layerConfig({...})` following the AnthropicClient per-field
Config idiom. *(Superseded — see Amendment 4: providers are values,
`Github.make` / `Github.makeConfig`, registered with `OAuthProviders.layer`.)*

## Config (src/config)

**AuthConfig** service: `baseUrl: string`, `basePath` (default "/auth"), `secret: Redacted<string>`,
`trustedOrigins: string[]`, `trustedProviders: string[]` (for implicit linking),
`session: {expiresIn, updateAge, freshAge}`, `emailPassword: {enabled, requireEmailVerification,
minPasswordLength}`, cookie overrides.

**Auth.layer(options)** — the batteries entry: merges defaults, provides AuthConfig +
crypto layers + SqlStores + Sessions/Passwords/Accounts + Events + Authenticated implementation +
RateLimits. `RIn`: `SqlClient | AuthEmails` (+ HttpClient when OAuth providers are configured).
**Auth.layerConfig** — same via per-field `Config` values (secret via `Config.redacted`).
Target consumer experience (this MUST work — it's the acceptance test):

```ts
const AuthLive = Auth.layer({
  baseUrl: "http://localhost:3000",
  secret: Redacted.make("..."),
  emailPassword: { enabled: true },
  providers: [Github.layer({ clientId, clientSecret })],
}).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
```

*(Superseded — see Amendments 5 and 6. The `providers` option is gone; the OAuth deployment is
`Auth.layerWithOAuth({ ..., providers: [Github.make({ clientId, clientSecret })] })`, and the set
of services the layer exposes is narrower than the list above.)*

## Client (src/client)

`AuthClient.make({ api?, baseUrl, httpClient? })` (or an `AtomHttpApi.Service` subclass — pick
what yields the best consumer types) wrapping AtomHttpApi against an `HttpApi` containing AuthApi:
- `session` query atom, `reactivityKeys: ["auth.session"]`.
- mutations `signIn`, `signUp`, `signOut`, `resetPassword`, ... — sign-in/up/out tagged with
  `["auth.session"]` so the session query auto-refetches.
- `signInSocial(providerId)` helper returning the redirect URL to navigate to.
Document the `AsyncResult.matchWithError` pattern (transport errors are defects in AtomHttpApi).
Browser-safe: no node builtins.

## Testing (src/testing)

`AuthTest.layer` — pglite SqlClient + migrations auto-run + `Auth.layer` with test config
(secret fixed, console-logging AuthEmails capture: a `TestEmails` service exposing a `Ref` of sent
mails so tests assert on delivered tokens) + scrypt with reduced params for speed.
Everything works under `it.effect` with TestClock (rolling refresh, expiry, freshAge tests).

## Example app (examples/basic)

Node server: `HttpApi.make("app").addHttpApi(AuthApi)` + one protected `GET /todos` group +
`Auth.layer` on pglite + console mailer; a small script (or vitest e2e) that exercises
sign-up -> verify-email -> sign-in -> get-session -> change-password -> sign-out via HttpApiClient.
This doubles as the integration test bed and the README's source of truth.

## Security checklist (verify each; reviewers audit against this list)

1. Session + verification tokens hashed (SHA-256) at rest; raw token returned exactly once.
2. Verification/state consumption is atomic single-use (DELETE...RETURNING semantics).
3. PKCE S256 always; state single-use, 10-minute TTL, nonce hashed at rest.
4. OAuth token/userinfo fetches refuse redirects (SSRF).
5. id_token verification fail-closed: iss, aud, exp, signature via JWKS, nonce when present.
6. No user enumeration: sign-in timing-safe (dummy-hash verify), reset/verification requests
   always return 200.
7. Open-redirect: all user-supplied URLs validated against trustedOrigins.
8. CSRF: sameSite=lax + Origin check on cookie-authenticated mutations.
9. Rate limits fail closed without a client IP.
10. Cookies: httpOnly, secure (https), __Secure- prefix when secure.
11. `Redacted` for passwords/secrets/tokens end-to-end + `Headers.CurrentRedactedNames`
    registration + a test asserting `<redacted>` rendering.
12. Password policy enforced server-side (8..128); scrypt params as specified.
13. Errors carry no secrets/PII beyond what the endpoint's contract requires.
14. Account linking gates: `(issuer, accountId)` first; implicit email-match only under the
    trust rules; unlink refuses removing the last method.

## Definition of done (v1)

- `pnpm install && pnpm build && pnpm test` green from a clean checkout.
- `pnpm check` (tsc --noEmit across src/test/examples) green.
- Example app runs and its e2e flow passes.
- OpenAPI JSON for AuthApi generates without throwing (snapshot test).
- README: pitch, attribution to better-auth, quickstart (the Auth.layer snippet), client usage,
  security notes, roadmap (v2: magic links, 2FA, cookie cache, Redis sessions, JWT, passkeys,
  plugin SDK, authz/Cedar).

## Amendments (post-review, v1)

Deviations from the endpoint table above that the implementation makes deliberately. Each was
raised in review and is recorded here rather than left as a silent difference from the contract.

1. **`resetPassword` / `verifyEmail` do not declare `TokenExpired`.** The table lists
   `InvalidToken, TokenExpired`; the implementation declares `InvalidToken` alone. This follows
   from this specification's own atomic-consume design: `VerificationStore.consume` is a single
   `DELETE … WHERE identifier = ? AND value_hash = ? AND expires_at > now RETURNING *`, so an
   expired token leaves no row to inspect and is indistinguishable from an unknown or an
   already-used one. Distinguishing them would need a second, unguarded read, which answers "a
   token was issued for this subject" to anyone who asks. `TokenExpired` remains defined in
   `Errors.ts` (documented as unreachable in v1) so that a future flow holding the row can raise it
   without a contract change.
2. **`signInSocial` additionally declares `RateLimited`.** The endpoint is unauthenticated and
   writes a `verifications` row per call, so it carries the credential bucket (3 per 10s per
   (IP, path)) — the same policy as sign-in and sign-up, and its own counter, since the path is
   part of the key. The cross-cutting rate-limit section already applies limits to endpoints whose
   table row does not mention them; this one is stated because it is client-visible.
3. **The OAuth callback's session is created outside the user+account transaction.** The
   `TransactionContext` note gives "OAuth sign-up = create user + account + session" as an example
   of a multi-store write. `Accounts.linkOAuth` commits user+account together and `Flow` creates
   the session afterwards, exactly as the password `signUp` path does (which this specification
   prescribes). A failure between the two leaves a user with no session and no partial identity;
   retrying the flow resolves as an ordinary sign-in through branch 1 of the linking algorithm.
   Threading a session factory through the linking algorithm to close the window would couple
   `Accounts` to `Sessions` for a case that is already recoverable.

### Tightening refactor (post-v1 API shape)

The four entries below are not deviations from the contract but amendments *to* it: they change
the shape of the public API, and supersede the corresponding paragraphs in the OAuth and Config
sections above. Behavior, endpoints, wire format, service keys and security properties are
unchanged — this was a shape-and-style pass, driven by REFACTOR.md, in which no test assertion
was weakened.

4. **Providers are values, not layers.** `Github.layer` / `Github.layerConfig` (and Google's
   equivalents) are gone, together with `Provider.layerEmpty` and `Provider.layerMerge`. An
   `OAuthProviderConfig` is inert data, so the constructors return it directly:
   `Github.make(options): OAuthProviderConfig` and
   `Github.makeConfig(options): Effect<OAuthProviderConfig, ConfigError>` (per-field `Config`
   values, the same fields as before). Registration is one call —
   `OAuthProviders.layer(providers): Layer<OAuthProviders>`, a static on the service class, equal
   to `Layer.succeed(OAuthProviders)(makeRegistry(providers))`. Registry semantics are untouched:
   null-prototype record, later ids override earlier, `ids` in registration order. This removes
   the `Layer.build` loop and the cast that stood at Provider.ts:358; the passage above reading
   "each with `Github.layer({...})` / `Github.layerConfig({...})`" should be read as
   `Github.make({...})` / `Github.makeConfig({...})`.

5. **Two entry points instead of one shape-shifting layer.** The single `Auth.layer(options)`
   whose type changed with the emptiness of a `providers` array is replaced by a pair, each with a
   fully explicit, non-generic signature:

   ```ts
   Auth.layer(options): Layer<Auth.Services, never, Auth.Requirements>
   Auth.layerWithOAuth(options): Layer<Auth.OAuthServices, never, Auth.OAuthRequirements>
   ```

   `Auth.layer` has no `providers` option, provides no `OAuthFlow` and requires no `HttpClient`.
   `Auth.layerWithOAuth` takes `providers: Auth.ProviderList` — a *non-empty* tuple of
   `OAuthProviderConfig` values — and adds `OAuthFlow` to what it provides and `HttpClient` to
   what it requires. `Auth.layerConfig` / `Auth.layerConfigWithOAuth` mirror the split, the latter
   taking a non-empty tuple of `Effect<OAuthProviderConfig, ConfigError>` (`ProviderConfigList`)
   composed inside the `Layer.unwrap`. Gone with them: `Auth.ProviderLayers`, the `Providers`
   generic on `Options` / `Extras` / `Services` / `Requirements`, both conditional types, the
   `providers.length` runtime branches and the final `as Layer.Layer<...>` cast. The acceptance
   snippet above is now `Auth.layerWithOAuth({ ..., providers: [Github.make({ clientId,
   clientSecret })] })`. Optionality is expressed by which function you call, not by a field that
   mutates a type.

6. **`Services` is narrowed to what a consumer composes against.** `Auth.layer*` exposes
   `AuthConfig`, `AuthEvents`, the four stores (`UserStore`, `SessionStore`, `AccountStore`,
   `VerificationStore`), `Sessions`, `Accounts`, `Passwords`, `Authenticated` and
   `RateLimiter.RateLimiter`; `layerWithOAuth` adds `OAuthFlow`. `Token`, `Hmac`,
   `PasswordHasher`, `OAuthProviders` and `WithAuthTransaction` are now provided *into* the stack
   and not out of it — they are implementation detail, replaced through the options rather than by
   shadowing a layer. `AuthHandlers.layer(api)` provided with either entry point still discharges
   completely, which is asserted at the type level in `test/config/Auth.types.ts`.

7. **Interface-split convention for every service.** Each `Context.Service` is now a bare key over
   a named, exported, JSDoc'd interface called `<ClassName>Service`, and every `make` states that
   interface as its return type: `SessionsService`, `AccountsService`, `PasswordsService`,
   `AuthEventsService`, `UserStoreService`, `SessionStoreService`, `AccountStoreService`,
   `VerificationStoreService`, `WithAuthTransactionService`, `PasswordHasherService`,
   `HmacService`, `TokenService`, `AuthConfigService`, `AuthEmailsService`,
   `OAuthProvidersService`, `OAuthFlowService`, and `TestEmailsService` in the test harness.
   `AuthConfigShape` was the one pre-existing name for such a shape and is now spelled
   `AuthConfigService` throughout. Two services are deliberately outside the convention and say so
   in their own JSDoc: `CurrentUser` and `CurrentSession` are keyed over the already-exported
   `User` and `Session` models, so there is no anonymous shape to extract and an alias would only
   add a second public name for one type. (`Authenticated` is an `HttpApiMiddleware.Service`, not a
   `Context.Service`; its type argument is a `provides`/`requires` descriptor, not a service
   shape.) Class names and service key strings are byte-identical to v1.

One consequence worth recording, because it removes something the API previously advertised:
`AuthHandlers.layer` and `AuthClient.make` now pin `groups.auth` to `typeof AuthApiGroup` rather
than to `HttpApiGroup.Constraint`, which is what reduces each of them to a single documented
boundary cast. `HttpApi.prefix` rewrites endpoint paths in the type, so a composed API that was
re-prefixed no longer satisfies that constraint and is rejected at compile time instead of being
mis-served. The `/auth` prefix is therefore fixed; serving the endpoints elsewhere is a deployment
concern (mount the server under a path, or put a rewriting proxy in front of it), and
`AuthConfig.basePath` remains how the library is told where they are publicly reachable, so
callback URIs and e-mail links agree with it.

## Amendments (v2): the session cookie cache

`src/http/SessionCache.ts` and the middleware path that reads it are new surface, not a deviation
from anything above. This section is the contract; the module's own JSDoc carries the same threat
statement for a reader who never opens this file.

### Format

The cookie's value is `base64url(json) + "." + base64url(HMAC-SHA-256(secret, json))`, and `json`
is `Schema.fromJsonString(CacheEnvelope)` of

```
{ v: 1, version: string, tokenHash: string, expiresAt: DateTimeUtcFromString,
  session: Record<string, unknown>, user: Record<string, unknown> }
```

The two halves are carried **already encoded** — what goes on the wire is exactly `Session.json` and
the model's `json` projection of the user, which is what `GET /auth/session` answers with. They are
decoded back through the *stored* variants (`Session`, `UserModel.decodeRow`), because a hit has to
answer with the same `Session` and `UserOf<F>` a database read would; re-encoding a decoded json
value to get there would be a third pass on every request. `tokenHash` is the base64url SHA-256 of
the session token the snapshot was minted for; it lives at the top level of the envelope, where it
is the binding, and `sessionSnapshot` therefore has no `tokenHash` of its own. Integrity only: the
payload is signed, never encrypted. A value over `maxCookieBytes` (3072) is skipped with a `Debug`
log rather than written, since a browser would drop it silently.

### Placement and arithmetic

In `MiddlewareLive.authenticate`, after the empty-credential guard and `checkOrigin`, before
`sessions.verify`. Cookie transports only — never bearer. A hit provides `CurrentUser` /
`CurrentSession` from the snapshot with no touch and no `Set-Cookie`; a miss runs `sessions.verify`
unchanged, re-sends the session cookie when the refresh moved the expiry, and then writes a fresh
snapshot.

Cache expiry is `min(now + cookieCache.maxAge, refreshDueAt(session), session.expiresAt)`. Clamping
to the refresh instant is what keeps the rolling refresh exactly as it was: the first request after
a session becomes refresh-due misses, touches and rewrites. Nothing in this module re-signs or
extends a session, and a snapshot whose computed lifetime is `<= 0` is not written at all.

### Authoritative reads

`Middleware.AuthoritativeSession` is a `Context.Reference<boolean>` (default `false`) read by the
middleware as `Context.get(options.endpoint.annotations, AuthoritativeSession)`. An annotated
endpoint bypasses the cache in **both** directions — no read, no write. It is an annotation rather
than a second middleware because a security middleware handler already receives the endpoint, and
because a plugin then opts in with one line on its own endpoint. Annotated in this library:
`changePassword`, `unlinkAccount`, `changeEmail`, `deleteUser`, `deleteUserCallback`, `setPassword`
— pinned as a list in `test/http-api/AuthApi.test.ts`, because an identity- or credential-changing
endpoint that forgets the line would act on a snapshot up to `maxAge` old. The annotation is a
`Context` annotation, so it is invisible to OpenAPI and to the generated client.

### Invalidation

`cookieCache.version: string | ((session, user) => string)` (default `""`) is compared on every
read; a mismatch is a miss. The function runs on the snapshot's own contents, so it invalidates when
the *deployment's* function changes, and it must be pure and cheap. `clearSessionCookies(config,
cache)` — session cookie *and* snapshot — is called by `signOut`, `revokeSessions`, `resetPassword`
and the delete-account paths; clearing only the session cookie would leave the person signed in
behind a snapshot nothing reads the database for. `updateUser` writes a fresh snapshot;
`verifyEmailChange` clears instead, since it is unauthenticated and has no `CurrentSession` to build
one from.

### Configuration and service

`AuthConfig.cookieCache: { enabled: false, maxAge: 5 minutes, version: "" }`, resolved with
`withDefaults`. Cookie names are `effect_auth.session_data` and its `__Secure-` twin, chosen by
`cookie.secure` exactly as the session cookie's are, and written with `sessionCookieOptions` so a
snapshot carries the credential's own `httpOnly` / `Secure` / `SameSite` / `path` / `domain`.

```ts
SessionCacheService<F> { enabled; encode(payload); decode(value): Option; read(credential); write(session, user); clear }
SessionCache.layerFor(model): Layer<SessionCache, never, AuthConfig | Hmac | Token>
```

A disabled deployment still gets the service, with every read a miss and every write and `clear` a
no-op, so nothing that depends on it has to branch on the configuration. `sessionCacheOf(model)` is
the typed view, as for the other field-sensitive readers.

### The trade, stated

Recorded here because switching this on is a security decision, not a performance one.

1. **Revocation lag.** A session revoked in one browser keeps answering in another for up to
   `maxAge`; so does a user row that changed. This is the cost, `maxAge` is its exact size, and the
   default is `enabled: false` so it is never paid unasked.
2. **Integrity, not confidentiality.** Anybody holding the cookie can read the payload. It is what
   the endpoint would have answered with, so that is not a leak — but nothing secret may be added to
   it, and a `UserField.hidden` column is deliberately absent.
3. **A hidden field is not carried**, so a cached read sees its declared *default*. An endpoint that
   reads one must be annotated `AuthoritativeSession`.
4. **Binding.** `tokenHash` is inside the signed payload and is compared against the digest of the
   credential presented, so a snapshot cannot be replayed beside another session, and swapping the
   two cookies is a miss rather than a confusion.
5. **Bearer clients gain nothing**, by construction: reading a cookie beside a bearer credential
   would let a cookie decide what a header-only request sees.
6. **It is not a defence.** Rotating `secret` invalidates every outstanding snapshot — an
   undecodable cookie is a miss, never a `401` — but the session tokens themselves are untouched.

### `Extras.sessionStore`

The related seam: `Auth.Options.sessionStore?: Layer<SessionStore, never, SessionStore>` is provided
the SQL stores and merged over them, so it may decorate or replace the one service this library
reads on the hot path. It is where a distributed session store plugs in; the other three stores are
deliberately not decorable. `AuthTest.countingSessionStore()` is the same seam in the harness, and
is how the suite proves a cache hit performs zero reads.

### Tests

`test/http/SessionCache.test.ts` (round trip, tampered payload and tag, another deployment's secret,
`sessionSnapshot` without `tokenHash`, each of the three `cacheExpiry` bounds, the service present
but off when disabled); `test/http/SessionCacheHttp.test.ts`, sequential over one
`countingSessionStore` (zero reads on a hit, garbage cookie, another browser's snapshot, a bumped
version, the `Max-Age` clamp and the touch on the request that finds the refresh due, a session
revoked elsewhere answering until the snapshot expires, authoritative endpoints reading and writing
nothing, sign-out / revoke-all / password-reset clearing both cookies, bearer untouched, the
opt-out default writing nothing, the `__Secure-` twin); `test/fields/Cache.test.ts` (a deployment's
own field in the snapshot, a hidden one absent from the cookie and defaulted on read).
