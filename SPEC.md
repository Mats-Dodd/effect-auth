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

## Amendments (v2)

The v2 wave added four things: a way for a deployment to put its own columns on the users table, an
extension seam and the first plugin built on it, the week-one endpoints v1 did not have, and the
zero-read session cookie cache `Hmac` was always reserved for. Almost none of it is a deviation from
the sections above — it is new surface — but every decision that a reader of those sections would
not predict is recorded here, and each amendment says what was chosen, what was rejected, and what
it costs.

Backward compatibility with v1 was **not** a goal of this wave; it fell out anyway, and §8 says how
far it goes.

The module map in "Module map & ownership" above gains, and nothing in it moved:

```
src/
  domain/       Verifications.ts (§9.3), Users.ts (§11)
  http/         SessionCache.ts (§12)
  oauth/        Discovery.ts (§11.2/18), providers/{Discord,Gitlab,Microsoft,Apple}.ts
  magic-link/   Api.ts, MagicLink.ts, Handlers.ts, index.ts  (§10 — the first plugin)
  client/       MagicLinkClient.ts, internal/atoms.ts
  internal/     records.ts
  testing/      MagicLinkTest.ts
```

### 8. The typed-view kernel: a deployment's own user fields

A deployment declares extra user columns once, as a field map, and every schema, store, endpoint,
handler and client that touches a user carries them. The design constraint that shaped everything
else: **no `Context.Service` key is re-created and none is made generic.** `Auth.Services`,
`AuthHandlers.HandlerServices`, every `Layer<…>` signature and both boundary casts are
byte-identical to what they were with no fields declared.

#### 8.1 One value, and typed views of the keys

The whole of `F` lives in one value, `UserModel<F>`, built by `makeUserModel(fields)`
(`Model.Struct({ ...Model.fields(User), ...fields })` plus `Model.extract` per variant). It carries
the six variants (`select`, `insert`, `update`, `json`, `jsonCreate`, `jsonUpdate`), the field map,
`extraKeys`, and the small operations the library needs to move extras across a boundary without a
cast — `makeInsert`, `completeInsert`, `decodeRow`, `basePatch`, `toPublic`, `extrasOf`,
`withExtras`.

Every constructor that *produces* users takes it: `SqlStores.layerFor(model)`,
`Passwords.layerFor(model)`, `Migrations.layerFor(model)`, `MiddlewareLive.layerFor(model)`,
`SessionCache.layerFor(model)`, `AuthHandlers.layer(api, model)`, `Auth.layer({ user: { model } })`.

Every reader that needs to *see* the fields gets a **typed view**: a second key object with the same
string id and the same `Identifier` type as the original, over a narrower `Shape`.

```ts
export const currentUserOf = <F extends UserFields>(model: UserModel<F>): Context.Service<CurrentUser, UserOf<F>>
// and: userStoreOf, sessionStoreOf, sessionsOf, passwordsOf, usersOf, sessionCacheOf
```

`yield* currentUserOf(model)` resolves the very slot `CurrentUser` resolves, and answers a
`UserOf<F>`. This is sound in one direction only, and that direction is the one the library needs:
reading a `UserOf<F>` through the *base* key is a widening (a `UserOf<F>` is a `User`), and only
this library's own layers ever write the slot. A consumer holding the base key sees the base
projection of a value that has more on it, which is what `GET /session` already does on the wire.

Rejected, and why:

- **An instance factory** (`Auth.define()` re-creating the key classes) makes every deployment's
  `Sessions` a *different type*, which infects `Services`, `HandlerServices` and every plugin's
  `Requirements` — a plugin could no longer name what it needs.
- **Pure generic threading** (F on the service interfaces themselves) is not expressible without
  `any` at the `Context.Service` boundary.
- **A namespaced `user.custom.*` sub-object** shortens no module list and breaks wire parity with
  better-auth's flat profile fields for no gain.

Naming convention, followed throughout: `X.make(model)` / `X.layerFor(model)` build for a model,
`xOf(model)` is the typed view, and every pre-existing constant (`User`, `UserPublic`,
`SessionWithUser`, `AuthApiGroup`, `SqlStores.layer`, `Passwords.layer`, …) remains exactly the
`baseUserModel` instance.

#### 8.2 The four field constructors

```ts
UserField.required(schema)                  // client must state it
UserField.withDefault(schema, () => value)  // client may state it; the model fills it in
UserField.readOnly(schema, () => value)     // Model.GeneratedByApp — readable, never settable
UserField.hidden(schema, () => value)       // Model.Sensitive — in every DB variant, in no JSON one
```

`hidden` is the one with a security consequence, and it is stated in three places because it holds
in all three: a hidden column never reaches a response body, never reaches the generated client, and
never reaches the cookie cache (§12.6). A cached read therefore sees a hidden field's *declared
default*; an endpoint that reads one must be annotated `AuthoritativeSession`.

#### 8.3 The provisionability rule

**Every extra field must be constructible without a value.** OAuth provisioning, a plugin's own
sign-up, and the base-typed `UserStore.create` all build a row from the base user fields alone;
`required` is therefore usable only alongside a constructor default of the schema's own.

Enforcement is a runtime check inside `makeUserModel`: `insert.makeOption(baseSample)` must be
`Some`, and a model that fails it throws at construction — at module scope, so a misdeclared field
is a start-up failure naming the field, never a sign-in that fails in production. The type-level
version of this rule needs a conditional constraint in an exported signature, which REFACTOR.md §1
forbids; the trade (a start-up throw instead of a red squiggle) is deliberate and is the only
runtime validation in the kernel.

The consequence a plugin author must know: **provision through the base-typed `UserStore`.**
`SqlStores.create` runs `model.completeInsert` on every row, so a deployment's own columns get their
declared defaults whether or not the writer knew they existed. `Auth.UserModelRef` (a
`Context.Reference` defaulting to `baseUserModel`) exists for a plugin that wants the model itself,
but the magic link plugin does not use it, because the base store already does the right thing —
see §10.5.

Excess and read-only keys in a payload are dropped silently rather than refused, which is Schema
v4's `onExcessProperty: "ignore"` default and matches better-auth's handling of provider profiles.

#### 8.4 The one sanctioned `ReturnType`

```ts
export type AuthApiGroupOf<F extends UserFields = {}> = ReturnType<typeof makeAuthApiGroup<F>>
export class AuthApiGroup extends makeAuthApiGroup(baseUserModel) {}
```

REFACTOR.md's ban on value-dependent types in exported signatures gets exactly one exception, here.
A group's type *is* the union of its twenty-eight endpoint types; writing it out means a second copy
of `makeAuthApiGroup` that no compiler keeps in step with the first, and `HttpApiGroup` is invariant
in its endpoints, so there is no wider type to state instead. The class wrapper is what keeps
`typeof AuthApiGroup` compact in the emitted `.d.ts`. No other `ReturnType` appears in an exported
signature in `src/`.

#### 8.5 What the parameterization costs

Three of the five permitted casts in `src/` exist because of this wave, each restated in
REFACTOR.md §5: `makeUserModel`'s re-typing of the erased build (`Schema.ts`), and the argument type
of the two mutation atoms whose payload mentions `F` (`AuthClient.ts`). `Handlers.ts` deliberately
narrows to the *base* group rather than `AuthApiGroupOf<F>`, so its twenty-eight handlers are
type-checked once rather than once per deployment; the extras of a payload are recovered through
`model.extrasOf` and the extras of a response are produced by `model.toPublic`, so the wire is
unaffected and the module's cast count is unchanged.

The type-checking cost is real and is recorded rather than hidden. Whole-repo
`tsc --noEmit --extendedDiagnostics` (src, tests and the example, which is how the v1 baseline was
taken), and the emitted declaration sizes both waves agreed to watch:

| Measure | v1 (`6b04380`) | v2 | Budget | |
|---|---|---|---|---|
| Types | 66,873 | 128,273 | ≤ 130,000 | ✓ |
| Instantiations | 309,786 | 723,591 | ≤ 620,000 | **✗ 17 % over** |
| Check time | 0.85 s | 1.32 s | ≤ 2.5 s | ✓ |
| Memory | 402 MB | 511 MB | – | |
| `dist/http/AuthApi.d.ts` | 21,627 B | 51,920 B | ≤ 3× (2.40×) | ✓ |
| `dist/client/AuthClient.d.ts` | 16,673 B | 20,818 B | ≤ 3× (1.25×) | ✓ |

Five of the six hold. **Instantiations are 17 % over the ceiling this wave set itself**, and that is
a knowingly-accepted overrun recorded here rather than a measurement to be re-taken: the check still
runs in well under a second and a half, and types — the measure that actually tracks editor
responsiveness — are inside their limit with 1 % to spare, which is the number to watch next. The
levers named when the budget was set are untouched and remain available: more class-wrapping of
default groups, and hand-written interfaces in place of the `ReturnType` in §8.4.

#### 8.6 Backward compatibility, and `Auth.define`

Every v1 name keeps its v1 type as the base instance, which is why the v1 suite needed no assertion
changed: `User`, `UserPublic`, `SessionWithUser`, `SignUpResponse`, `CurrentUser`, `Authenticated`,
`AuthApiGroup`, `AuthApi`, `AuthHandlers.layer(api)`, `AuthClient.make()`, `Auth.layer(options)`,
`SqlStores.layer`, every `*.layer`, `AuthTest.*`, `UserPatch`, `SignUpOptions`. The OpenAPI document
is identical because each variant is re-annotated back to `effect-auth/User.<variant>` after
extraction, and `test/fields/Default.test.ts` asserts that `makeUserModel({})`'s variants are
structurally the `User` ones.

`Auth.define({ user: { fields } })` returns the bundle — model, schemas, typed views, group, API,
handlers, all four entry points, migrations — and is convenience over the per-module functions, not
a second source of truth. It is deliberately not browser-safe and carries no client; a browser
passes the model to `AuthClient.make({ api, model })`.

### 9. The plugin SDK

#### 9.1 A plugin is a module, not a registration

There is no plugin object, no `plugins: [...]` array and no lifecycle. A plugin exports
`{ XApiGroup, Options, layer(options), handlers(api), XClient?, Migrations?, testing? }` and a
consumer composes it with plain layers:

```ts
const AuthLive = Auth.layer(opts).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
const PluginLive = X.layer({ … }).pipe(Layer.provideMerge(AuthLive), Layer.provide(MyXMailer))
const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(X.XApiGroup).add(Todos)
const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), X.handlers(AppApi), Todos.layer)
  .pipe(Layer.provide(PluginLive))
```

An `AuthPlugin<…>` value plus `Auth.layerWith({ plugins })` was designed and rejected: it needs
heterogeneous-tuple inference — the type gymnastics REFACTOR.md exists to keep out — to say
anything a plain `Layer.mergeAll` does not already say, and every field of it is already an Effect
primitive. Group ids are camelCase (`magicLink`), path prefixes are `/auth/<kebab>`. Two groups
sharing an identifier collide silently in `HttpApi`, so an id is a plugin's namespace and must be
picked like one.

#### 9.2 `AuthHandlers.forGroup` and `AuthHandlers.dieOn`

```ts
AuthHandlers.forGroup(group, build)(api): Layer<HttpApiGroup.Service<ApiId, Id>, …>
AuthHandlers.dieOn(tags)(effect)   // serverFaultTags = ["PasswordHashError", "PersistenceError"]
```

`HttpApiBuilder.group` takes the API a group was *added to*, and a library cannot name the API a
consumer will compose. `forGroup` is that boundary written once — the cast documented in
REFACTOR.md §5.1, which this wave widened from `layer`'s private use to a public door. Both callers
pin `api.groups[id]` to the group value they were handed, so an API carrying a *different* group
under the same identifier is a compile error rather than a mis-served route. `layer` is now
literally `forGroup(AuthApiGroup, …)`, so the plugin path and the core path are the same path.

`dieOn` turns named infrastructural tags into defects, which is how an endpoint's declared error
union stays the client contract rather than a list of everything that can go wrong underneath it.

#### 9.3 `Verifications` — the lifted single-use token

`src/domain/Verifications.ts` lifts what `Passwords` used to do privately into a service every
feature and plugin uses. Identifier strings, hashing and the atomic `consume` are unchanged, so no
row format moved.

```ts
purpose(name), purpose(name, payloadSchema)   // TokenPurpose<P>
identifierOf(purpose, subject) === `${purpose.name}:${subject}`
issue({ purpose, subject, ttl, payload }) → { token, expiresAt, identifier }
claim(purpose, token)   → { subject, payload, identifier, verification } | InvalidToken
retire(purpose, subject) → number
```

The token a caller receives is the composite `<base64url(subject)>.<secret>` v1 already used for
reset links, so the row can be named without a second lookup; only the secret half is hashed and
stored. A malformed token, a missing row, an expired row and a payload that no longer decodes are
**all** `InvalidToken` — the same indistinguishability amendment 1 records for `resetPassword`.

The purposes in this library: `email-verify`, `password-reset`, `magic-link`,
`change-email-confirm`, `change-email-verify`, `delete-account`. `oauth-state:` rows are still
minted by `oauth/State.ts` directly, because state carries a code verifier and a link target rather
than a subject.

#### 9.4 `Services` widened

Amendment 6 narrowed `Auth.Services` to what a consumer composes against. A plugin composes against
more, so the union grows by six: `WithAuthTransaction`, `Token`, `Hmac`, `Verifications`,
`SessionCache` and `Users`. `PasswordHasher` and `OAuthProviders` stay internal — a plugin has no
business hashing a password or reading the provider registry — which meant splitting the crypto tier
so `Token` surfaces through `provideMerge` while the hasher is still `provide`d. `Hmac` is now built
inside `compose` from the configured secret rather than being a layer a consumer supplies.

`Extras.sessionStore` is the other new seam (§12.7). `ConfigOptions` gains `user` and `cookieCache`.

#### 9.5 `PluginEvent`

`AuthEvent` is a closed union, so a plugin cannot add a member to it. It gets one instead:

```ts
PluginEvent { plugin: string, event: string, userId: UserId | null, data: Record<string, unknown> }
```

The same rule as every other member applies to `data` and is written on the schema: no token, no
password, no hash, no provider credential. Events reach log sinks and webhooks.

#### 9.6 Per-plugin migration tables

```ts
Migrations.make({ table, migrations }): MigrationSet   // { migrations, loader, run, layer }
```

`Migrator.fromRecord` orders **globally and numerically**, so a lower id added later never runs. A
plugin therefore ships its ids from `0001` in its own bookkeeping table
(`effect_auth_<plugin>_migrations`), sequenced with
`Plugin.Migrations.layer.pipe(Layer.provide(Migrations.layer))`. Merging a plugin's records into
this library's is the one thing a plugin must never do: this library will add a `0005` one day, and
it would silently never run. The core set is refactored onto `Migrations.make` and keeps its table
name, `effect_auth_migrations`.

#### 9.7 Per-plugin mailers

A core flow that needs a message extends `AuthEmailsService` — correct, because every deployment
implements that interface and a core flow is part of what a deployment signed up for. **A plugin
gets a mailer service of its own**, carried in its `Requirements`. Two reasons, and the second is
the load-bearing one: a plugin cannot widen an interface every existing deployment implements, and
the shapes genuinely differ — `MagicLinkEmails.sendMagicLink` takes `user: User | null`, because the
address may have no account and the endpoint must not reveal which. Forgetting to provide it is a
compile error at the composition site.

#### 9.8 Harness seams

`TestEmails` is now kind-keyed (`EmailKind = string` plus named constants) and exposes
`record(email)` — the seam a plugin's test mailer implements over, honouring `delivery: "failing"`
exactly as the library's own does. `to` / `last` / `tokenFor` filter on the recipient address, which
is what makes an unknown-address test assertable. `AuthTest.layerHttpApi(api, options, extra)` gives
a plugin's handler layer the *same* `layer(options)` build the auth handlers get, so both groups
read one `Sessions`, one `UserStore` and one rate limiter. `AuthTest.countingSessionStore()` and the
two `TestHttpClient` cookie helpers exist for §12.

### 10. Magic link — the first plugin

`src/magic-link/` is the worked example of §9 and a feature in its own right: passwordless sign-in
by a single-use link. It owns **no table** — a link is a `Verifications` token — so a deployment
that has run this library's migrations needs no new ones.

| id | method / path | bucket | success | errors |
|---|---|---|---|---|
| `signIn` | `POST /auth/magic-link/sign-in` | `email` 3/60s | `Ok`, always | `RateLimited` |
| `verify` | `GET /auth/magic-link/verify?token=` | `credentials` 3/10s | `302` | `RateLimited` |
| `exchange` | `POST /auth/magic-link/exchange` | `credentials` | `SessionWithUser` + cookie | `InvalidToken`, `SignUpDisabled` 403, `RateLimited` |

`Options { ttl = 5 min, disableSignUp = false, path = "/auth/magic-link/verify",
revokeUnprovenAccounts = true }`.

#### 10.1 Enumeration safety and the URL rules

`signIn` answers `200` for every well-formed address — registered, unregistered, and one whose
message could not be delivered (logged and swallowed). With `disableSignUp` on, an unknown address
gets no token and no mail, and still `200`.

The three callback URLs travel in the token's **server-side payload**, never in the link, so a link
cannot be edited into one that lands somewhere else. Each is validated against `trustedOrigins` when
the link is minted and **dropped rather than refused** if it does not survive that: a bad URL in a
sign-in request is a caller's bug, and failing the request would make the endpoint distinguish
requests it must answer identically. `verify` redirects on failure too, to the link's own
`errorCallbackURL` carrying `?error=invalid_token` or `?error=sign_up_disabled`, else to `baseUrl`.
A link that created the account lands on `newUserCallbackURL ?? callbackURL`.

#### 10.2 The unproven-account rule

The attack: register an address you do not own, wait, and hope its real owner later signs in with a
magic link — you would then share the account. So when a link proves control of an address whose
account is **unverified**, that account's sign-in methods and sessions are destroyed in one
transaction and the address is marked verified (`AccountUnlinked` ×n, `SessionRevoked{all}`,
`EmailVerified`, and a `PluginEvent{ plugin: "magic-link", event: "UnprovenAccountRevoked" }`).

`revokeUnprovenAccounts: false` keeps the credential and the sessions. It does **not** keep the
address unverified: delivering a link to an address and having it come back proves control of it
either way, so the option gates only the destruction, which is a narrower reading than the design
note had. Switch it off only if something else in the deployment guarantees no account is ever
created unverified.

#### 10.3 Deviations from the plan, recorded

1. **Users are provisioned through the base-typed `UserStore`, not `UserModelRef`.** An
   `AnyUserModel`'s `makeInsert` answers the erased `UserRow`, which is not assignable to the
   base-typed `create` without a cast the gate forbids. The plugin does what `Accounts.ts` does —
   `insertRow(User.insert, …)` then `users.create(row)` — and §8.3's `completeInsert` gives a
   deployment's own columns their defaults regardless. `UserModelRef` remains, unused by this
   plugin.
2. **The group is not parameterized by user fields.** `MagicLinkApiGroup` and `MagicLinkClient` are
   non-generic, which is what Part B asked for and what keeps the plugin cast-free. The consequence
   is client-visible and is documented in the module: in a deployment with custom user fields,
   `POST /auth/magic-link/exchange` answers the **base** user projection. The custom fields are one
   `GET /auth/session` away, and the cookie `exchange` set works immediately.
3. **`request` does look the user up**, though the design said it need not: the mailer takes
   `user: User | null`, so there is nothing to send without the lookup. The result is branched on
   only under `disableSignUp`, which is the one latency asymmetry, and it is the same one
   `Passwords.requestReset` already carries and documents.
4. **`reclaim` reads with `listByUserIdForUpdate`** (a row lock) rather than a plain read, because
   it is a check-then-act over the set of a user's sign-in methods.
5. `MagicLinkTest.Options` extends `AuthTest.Settings` rather than `AuthTest.Options<F>`, because
   its `TestApi` composes the base auth group. A custom-field magic-link test builds its own API
   from `makeAuthApi(model)` plus `MagicLinkApiGroup`.

### 11. Core parity: ten endpoints, four providers, discovery

#### 11.1 The endpoints

Added to `AuthApiGroup`, taking it from eighteen to twenty-eight. `AuthoritativeSession` (§12.3) is
marked ▲.

| id | method / path | auth | errors beyond 500 | bucket |
|---|---|---|---|---|
| `updateUser` | `POST /update-user` | session | `UserNotFound` | – |
| `changeEmail` | `POST /change-email` | session + fresh ▲ | `EmailUnchanged`, `SessionNotFresh`, `RateLimited` | credentials |
| `confirmEmailChange` | `GET /change-email/confirm?token=` | none | `InvalidToken` | – |
| `verifyEmailChange` | `GET /change-email/verify?token=` | none | `InvalidToken`, `UserAlreadyExists` | – |
| `deleteUser` | `POST /delete-user` | session ▲ | `InvalidCredentials`, `SessionNotFresh`, `RateLimited` | credentials |
| `deleteUserCallback` | `GET /delete-user/callback?token=` | session ▲ | `InvalidToken` | – |
| `setPassword` | `POST /set-password` | session + fresh ▲ | `PasswordAlreadySet`, `PasswordPolicyViolation`, `SessionNotFresh`, `RateLimited` | credentials |
| `getAccessToken` | `POST /get-access-token` | session | `NotFound`, `TokenRefreshFailed` | – |
| `refreshToken` | `POST /refresh-token` | session | `NotFound`, `TokenRefreshFailed` | – |
| `oauthCallbackForm` | `POST /callback/:providerId` | none | – | – |

`changePassword` and `unlinkAccount` gained the ▲ annotation. Provider tokens cross the wire as
`Secret = Schema.Redacted(String)` — `Redacted` in every process, a string on the wire.
`user.changeEmail.enabled` and `user.deleteUser.enabled` default to `false`, and a deployment that
leaves them off answers `404` (`notServed`) on those five paths: they are in the contract and not
served here, exactly as the credential endpoints are with `emailPassword.enabled: false`.

#### 11.2 Deliberate divergences from better-auth

Each of these is a considered difference, not an oversight.

1. **Change-email is always mail-based.** There is no `updateEmailWithoutVerification`. It requires
   a *fresh* session, and it is two-hop: a confirmation to the address the account has now (when
   that address is verified), then a verification to the new one. The new address lives in the
   token's payload and never in a URL.
2. **The uniqueness check for a change of address is the unique index at hop two**, surfacing as
   `UserAlreadyExists`. Hop one answers `200` whether or not the address is free, because a
   distinguishable answer makes the endpoint an oracle for who is registered here. `hop 2` is also
   deliberately *not* re-checked against the account's current address.
3. **A completed change ends `emailVerified: true`** — the link was delivered to the address it
   names — and **other sessions are not revoked**. Nothing about the account's credentials changed.
4. **Both `requestEmailChange` and `requestDeletion` retire their purpose's outstanding tokens
   before minting a new one**, so a person who asks twice has exactly one live link. Two live links
   are two addresses an account could still be moved to, one of which its owner has already thought
   better of.
5. **The callbackURL reaches only the hop that `requestEmailChange` itself sent.** The second hop
   issued by `confirmEmailChange` carries none: `ChangeEmailPayload` is `{ newEmail }`, and widening
   it would put a caller-supplied URL into a row read back on an unauthenticated path.
6. **Delete-user's direct path requires a fresh session** and answers `SessionNotFresh` (403) when
   it is stale, rather than falling back to a mail. With `confirmByEmail` on it always mails
   (24 h TTL) and answers `ConfirmationSent`, and nothing is removed until the link is followed.
   `confirmDeletion` claims the token **first** and only then checks the subject against the caller,
   so a link presented by anybody else is burnt as well as refused.
7. **`requestDeletion` turns a `PasswordHashError` into a defect.** The frozen `UsersService`
   channel is `InvalidCredentials | SessionNotFresh | PersistenceError`; the handler's `serverFault`
   would have made a defect of it one layer up anyway, so it is caught at the domain boundary rather
   than widening a frozen interface.
8. **`setPassword` is an HTTP endpoint, and can never replace a password.** An existing hash is
   `PasswordAlreadySet` (409); the insert race is settled by the unique index into the same error.
   It requires a fresh session and revokes nothing — no credential was invalidated. The remaining
   check-then-act (a credential row that exists with a `NULL` hash) is last-write-wins; that state
   is not reachable through anything this library writes, and closing it needs a conditional
   `UPDATE … WHERE password_hash IS NULL RETURNING` in a store this wave did not open.
9. **`UserUpdated.fields` names only base fields that actually changed**, which costs one `findById`
   before the write — the same read that produces `UserNotFound`. An update touching only custom
   columns publishes `fields: []`.
10. **`scope` is never written by a token refresh** (the key is omitted, not nulled), and neither is
    a refresh token the provider did not rotate, nor a stored `id_token` when the response carries
    none. A rotated refresh token is written together with its new expiry.
11. **`accessToken` refreshes iff** the access token is absent **or** its stated expiry is within
    `accessTokenSkew`, **and** the account has a refresh token, **and** the provider is registered
    with `tokenRefresh.enabled !== false`. An expiry the provider never stated is treated as "not
    expiring". When a refresh is warranted but impossible the stored token is handed back rather
    than failing; only an account with no access token *and* no way to get one is
    `AccessTokenMissing`. A refresh that is attempted and *refused* fails (`RefreshRejected`) even
    though a stale token exists.
12. **`TokenRefreshFailed` has no `ClientSecretUnavailable` reason.** A secret that cannot be minted
    during a refresh is `ProviderUnavailable`, because nothing reached the provider. The exchange
    path still reports `ClientSecretUnavailable` through `OAuthProviderError`.
13. **Apple uses `response_type=code`, not the hybrid flow**, and needs no `trustedOrigins` entry —
    the callback is unauthenticated. Asking for the `name` scope makes Apple `POST` the callback
    cross-site, which `oauthCallbackForm` answers with a `302` to its `GET` twin carrying the same
    parameters, because a cross-site POST carries no `SameSite=Lax` cookie.
14. **`Apple.idTokenAudience = audience ?? appBundleIdentifier ?? clientId`.** better-auth's rule
    (`appBundleIdentifier ?? clientId`) *replaces* the Services ID, so a deployment serving web and
    native would refuse its own web tokens. The explicit `audience` option is the both-clients
    escape hatch.
15. **`Microsoft.userInfo` falls back to `preferred_username`** when the optional `email` claim is
    absent, which better-auth does not — Entra omits it unless the app registration asks. That
    address is **never** verified: `emailVerified` is false whenever the `email` claim is missing,
    so a UPN can never link onto an existing local account by itself. There is no Graph photo fetch.
16. **`Microsoft.issuer` is set to `${authority}/${tenant}/v2.0` even for `common` /
    `organizations` / `consumers`**, a string no token ever claims, because the *presence* of
    `issuer` is what puts the flow on the OIDC path. `issuerOf` (derived from the token's own `tid`)
    is what is actually compared, and the per-identity `info.issuer` stored on the account is the
    verified `iss`, so nothing is ever stored under the synthetic value.
17. **`Gitlab` is plain OAuth2** although GitLab publishes an issuer: `state` and `locked` are only
    visible on `GET /api/v4/user`, and an absent `state` fails closed.
18. **`OidcDiscovery` narrows the advertised signing algorithms to the asymmetric families** before
    using them, because a document advertising `HS256` would name an algorithm keyed by the client
    secret on the provider's own say-so. `issuer` is a required option and must equal the discovered
    one byte-for-byte; a document with no `jwks_uri` and no pinned key set is `KeysMissing` rather
    than a skipped signature check. The body read gets its own `providerRequestTimeout`.
19. **Provider tokens are stored unencrypted at rest.** Recorded as a known gap, not a decision to
    leave alone forever.

#### 11.3 Shape notes worth recording

- `OAuthFlow.make` / `layer` additionally require `AccountStore`: the flow needs
  `findByIdAndUserId` / `updateTokens`, which `AccountsService` does not expose, and `Auth.ts`
  already annotates `AuthStores` in the tier's `RIn`. Widening the frozen `AccountsService` was the
  alternative.
- `tokenRequest` takes one options object `{ provider, params, extraParams?, failures }` rather than
  the sketched `(provider, body, failure)`: the exchange and the refresh fail in the same three ways
  but report them as different error types, and the client-secret case must pass a provider's own
  `OAuthProviderError` through unchanged. `extraParams` is filtered by `reservedTokenParams` and
  written before the flow's own, so a configured `client_id` can neither override nor duplicate.
- `UsersService`'s `Requirements` alias still lists `VerificationStore` although `make` no longer
  resolves it (every row goes through `Verifications`). `Effect`'s `R` is covariant, so the
  annotated return type still checks, and narrowing a frozen alias that `Auth.compose` is written
  against was not worth it.
- `oauthCallback` forwards `query.user` into `CallbackOptions.params`, which is what carries Apple's
  one-shot display name from the form post to `provider.userInfo(tokens, { params })`. It is the one
  place a provider reads an unsigned value, and it is used for the display name and nothing else.

### 12. The session cookie cache

`src/http/SessionCache.ts` and the middleware path that reads it are new surface, not a deviation
from anything above. This section is the contract; the module's own JSDoc carries the same threat
statement for a reader who never opens this file.

#### 12.1 Format

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

#### 12.2 Placement and arithmetic

In `MiddlewareLive.authenticate`, after the empty-credential guard and `checkOrigin`, before
`sessions.verify`. Cookie transports only — never bearer. A hit provides `CurrentUser` /
`CurrentSession` from the snapshot with no touch and no `Set-Cookie`; a miss runs `sessions.verify`
unchanged, re-sends the session cookie when the refresh moved the expiry, and then writes a fresh
snapshot.

Cache expiry is `min(now + cookieCache.maxAge, refreshDueAt(session), session.expiresAt)`. Clamping
to the refresh instant is what keeps the rolling refresh exactly as it was: the first request after
a session becomes refresh-due misses, touches and rewrites. Nothing in this module re-signs or
extends a session, and a snapshot whose computed lifetime is `<= 0` is not written at all.

#### 12.3 Authoritative reads

`Middleware.AuthoritativeSession` is a `Context.Reference<boolean>` (default `false`) read by the
middleware as `Context.get(options.endpoint.annotations, AuthoritativeSession)`. An annotated
endpoint bypasses the cache in **both** directions — no read, no write. It is an annotation rather
than a second middleware because a security middleware handler already receives the endpoint, and
because a plugin then opts in with one line on its own endpoint. Annotated in this library:
`changePassword`, `unlinkAccount`, `changeEmail`, `deleteUser`, `deleteUserCallback`, `setPassword`
— pinned as a list in `test/http-api/AuthApi.test.ts`, because an identity- or credential-changing
endpoint that forgets the line would act on a snapshot up to `maxAge` old. The annotation is a
`Context` annotation, so it is invisible to OpenAPI and to the generated client.

#### 12.4 Invalidation

`cookieCache.version: string | ((session, user) => string)` (default `""`) is compared on every
read; a mismatch is a miss. The function runs on the snapshot's own contents, so it invalidates when
the *deployment's* function changes, and it must be pure and cheap. `clearSessionCookies(config,
cache)` — session cookie *and* snapshot — is called by `signOut`, `revokeSessions`, `resetPassword`
and the delete-account paths; clearing only the session cookie would leave the person signed in
behind a snapshot nothing reads the database for. `updateUser` writes a fresh snapshot;
`verifyEmailChange` clears instead, since it is unauthenticated and has no `CurrentSession` to build
one from.

#### 12.5 Configuration and service

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

#### 12.6 The trade, stated

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

#### 12.7 `Extras.sessionStore`

The related seam: `Auth.Options.sessionStore?: Layer<SessionStore, never, SessionStore>` is provided
the SQL stores and merged over them, so it may decorate or replace the one service this library
reads on the hot path. It is where a distributed session store plugs in; the other three stores are
deliberately not decorable. `AuthTest.countingSessionStore()` is the same seam in the harness, and
is how the suite proves a cache hit performs zero reads.

#### 12.8 Tests

`test/http/SessionCache.test.ts` (round trip, tampered payload and tag, another deployment's secret,
`sessionSnapshot` without `tokenHash`, each of the three `cacheExpiry` bounds, the service present
but off when disabled); `test/http/SessionCacheHttp.test.ts`, sequential over one
`countingSessionStore` (zero reads on a hit, garbage cookie, another browser's snapshot, a bumped
version, the `Max-Age` clamp and the touch on the request that finds the refresh due, a session
revoked elsewhere answering until the snapshot expires, authoritative endpoints reading and writing
nothing, sign-out / revoke-all / password-reset clearing both cookies, bearer untouched, the
opt-out default writing nothing, the `__Secure-` twin); `test/fields/Cache.test.ts` (a deployment's
own field in the snapshot, a hidden one absent from the cookie and defaulted on read).
