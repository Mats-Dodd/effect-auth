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

Coding conventions and the module map live in `AGENTS.md`.

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
class CurrentSession extends Context.Key<CurrentSession, Session>()("effect-auth/http/Middleware/CurrentSession") {}
class CurrentUser extends Context.Key<CurrentUser, User>()("effect-auth/http/Middleware/CurrentUser") {}
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

> **Superseded by Amendment 19.5.** `requireFresh` and `SessionNotFresh` are deleted. Freshness is
> one member of one `AssurancePolicy` — `{ maxAge }`, measured from the session's `authenticatedAt`
> — stated on an endpoint as the `RequireAssurance` annotation and refused with `StepUpRequired`
> (403). Every `SessionNotFresh` in the sections below reads as `StepUpRequired`.

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

*(Superseded — see Amendment 15: the OIDC settings are one `oidc` block whose `keys` is a required
union, and an optional `exchange` override can take over the code exchange.)*

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

> **Superseded by Amendment 19.** `src/magic-link/`, `src/client/MagicLinkClient.ts` and
> `src/testing/MagicLinkTest.ts` were deleted in the Phase 1 wave. `src/email-otp/` is the reference
> plugin §9 and §10 describe, and it carries magic link's link flow with it. The map as it stands
> after that wave is Amendment 19's, below.

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
never reaches the cookie cache (§12.6). A model containing one disables cache reads entirely;
request authentication always resolves its authoritative database row.

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
declared defaults whether or not the writer knew they existed. `UserModelRef` (a flat export from
`effect-auth`; a `Context.Reference` defaulting to `baseUserModel`) exists for a plugin that wants the model itself,
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

Type-checking cost is not budgeted. Whole-repo check time under tsgo is well under a second; if it
ever becomes noticeable, the one `ReturnType` in §8.4 is where to look. (An earlier instantiation
budget stood here; it was taken with TypeScript 5's counters, which tsgo does not share, and was
retired in Amendment 18.)

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
under the same identifier is a compile error rather than a mis-served route. `forGroup` and `layer`
are the two public doors onto one private `buildGroup`, which holds the cast; `layer` cannot go
through `forGroup` itself, because `forGroup` would pin `groups["auth"]` to `typeof AuthApiGroup`
while `layer`'s API carries `AuthApiGroupOf<F>`. The plugin path and the core path are still the
same path — the cast is written once, in `buildGroup`.

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

> **Amendment 19.** `magic-link` is gone with its module. The purposes the Phase 1 plugins add:
> `email-otp:{sign-in, verify-email, reset-password, step-up, change-email}`, `pending-auth`,
> `passkey-challenge`, and `phone:{verify, signIn, stepUp}`. Every purpose a `Challenges` code is
> issued under **must** declare a payload schema — see 19.7 for why a payload-less one leaves the
> challenge row redeemable as a link token.

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

> **Superseded by Amendment 19.9.** This module was deleted in the Phase 1 wave and `src/email-otp/`
> took its place as the reference plugin — the single-use link included, at
> `GET /auth/email-otp/link?token=`. The section is kept because everything it establishes still
> holds: the enumeration rules of §10.1, the unproven-account rule of §10.2 (which now runs on three
> purposes and also sweeps contributed authenticators), and the five recorded deviations of §10.3.
> Read the endpoint table below as history; 19.9 says what replaced it and why.

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
`errorCallbackURL` carrying `?error=invalid_token`, `?error=sign_up_disabled` or
`?error=policy_refused&code=<the hook's code>` (§13.3), else to `baseUrl`.
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

1. **Users are provisioned through the base-typed `UserStore`, not `UserModelRef`.**
   `AnyUserModel.makeInsert` / `completeInsert` answer the base-typed insert row (`UserInsertOf<{}>`),
   so the seam's documented use does compile against `UserStore.create` — but the plugin does what
   `Accounts.ts` does — `insertRow(User.insert, …)` then `users.create(row)` — because §8.3's
   `completeInsert` gives a deployment's own columns their defaults regardless, and one fewer service
   is one fewer thing a plugin can misuse. `UserModelRef` remains, unused by this plugin.
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
   `UserAlreadyExists`. Hop one answers `200` **and mails the hop-1 confirmation to the caller's own
   verified address whether or not the new address is free**: a taken address that produced no mail
   would let an account holder enumerate registrations from their own mailbox. `confirmEmailChange`
   re-checks availability at claim time and, when the address is taken, silently sends no hop 2 —
   so the caller's observable outcome (response, mail count and kind) is identical for a free and a
   taken address, and the occupied address is never written to. When the caller's *current* address
   is unverified there is no hop 1 to send, so both paths return before any write or mail and the
   only residual channel is latency (one `findByEmail` versus one `findByEmail` plus an early
   return) — recorded as accepted, not closed. Hop 2 is also deliberately *not* re-checked against
   the account's current address.
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
   **Freshness is checked before the optional password is verified, on both paths**: a request
   that offers a password from a stale session is `SessionNotFresh` whether the password is right
   or wrong, so a stolen stale cookie cannot use this endpoint as a password oracle (the
   `credentials` bucket alone would only have halved the guess rate).
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
19. **Provider tokens are encrypted at rest.** The SQL store uses AES-256-GCM under a key derived
    from `AuthConfig.secret`; account id and token kind are authenticated as associated data. A
    secret rotation therefore needs a re-encryption migration (or provider relinking), and legacy
    plaintext rows are intentionally rejected.

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

The cookie's value is `base64url(json) + "." + base64url(HMAC-SHA-256(secret, macContext + json))`,
where `macContext` is the constant `"effect-auth/session-cache/v1\n"` (`SessionCache.macContext`) —
the `Hmac` service is shared with any other feature that signs under the deployment secret, so the
tag is domain-separated: a tag produced over some other message can never verify as a snapshot, and
vice versa. `json` is `Schema.fromJsonString(CacheEnvelope)` of

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
`changePassword`, `unlinkAccount`, `changeEmail`, `deleteUser`, `deleteUserCallback`, `setPassword`,
`getAccessToken`, `refreshToken` — pinned as a list in `test/http-api/AuthApi.test.ts`, because an
identity- or credential-changing endpoint that forgets the line would act on a snapshot up to
`maxAge` old, and the two token endpoints hand out provider credentials that a revoked-elsewhere
session must not be able to fetch from a cached cookie. The annotation is a
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
3. **A hidden field is not carried**, and a model containing one disables cache reads entirely so
   no authorization decision can see a fabricated default.
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

### 13. Policy hooks

`src/domain/Hooks.ts` is a small set of **semantic** points at which core asks whoever installed
hooks whether to proceed, and — at one of them — what the row should say. It exists because a
deployment or a plugin needs to veto or enrich core operations ("no sign-ups outside this domain",
"set `role` from the OAuth profile", "write the tenant row atomically with the user") and the only
answer before it was decorating a service with `Layer.provideMerge`, which is whack-a-mole: users
are created from three different flows, and a decorator only affects consumers above it.

Deliberately **not** built: request-level `before`/`after` (an `HttpApiMiddleware` already does
that), generic CRUD hooks on every store method (the store decorator seams do that — §12.7), an
update hook (add `beforeUserUpdate` the day something needs it), and after-commit side effects
(`Auth.events` does that, and stays fire-and-forget).

#### 13.1 The six points, and exactly when each is consulted

| hook | where | the moment |
|---|---|---|
| `beforeUserCreate` | `Users.provision`, and the same sequence in `Passwords`/`Accounts` (13.2) | after the candidate row is built and before it is written; may rewrite or refuse |
| `afterUserCreate` | same three | after `userStore.create`, inside the same transaction |
| `beforeSessionCreate` | `Passwords.signUp` (auto-session), `Passwords.signIn`, `oauth/Flow` callback, magic-link `verify` | immediately before `sessions.create`, **after** the credential has been verified |
| `beforeEmailChange` | `Users.requestEmailChange` | after the `EmailUnchanged` guard, **before** the lookup that forks taken/free, and before any token is minted or mailed |
| `beforeUserDelete` | `Users.requestDeletion`, `Users.confirmDeletion` | after the freshness guard *and* the password check; on the mail-confirmed shape again **after the token is claimed** |
| `beforeAccountLink` | `Accounts.linkOAuth` (implicit linking) and `Accounts.linkToUser` (`linkSocial`) | before a provider identity is attached to a user that **already exists** — never on first provision, which is `beforeUserCreate`'s job |

Every member is optional; absent means "allow, unchanged". Each ordering above is load-bearing and
is pinned by a test:

- `beforeSessionCreate` runs **after** verification so that the constant-cost `hasher.verify` of the
  sign-in path is not skipped and a refusal reveals nothing a correct password would not have
  revealed. `test/domain/Hooks.test.ts` proves exactly one verify with `countingHasher`.
- `beforeEmailChange` runs **before** the taken/free fork so the enumeration posture of that flow is
  unchanged: a policy that ran after it would answer differently per branch, or pay for a lookup it
  does not use.
- `beforeUserDelete` on `confirmDeletion` runs **after** the claim: a refused link is spent, not
  parked and replayed against a policy that has since changed its mind.
- `Sessions.create` itself stays hook-free — it is also test and plumbing surface; the four sign-in
  paths call the hook, not the session service.

#### 13.2 The choke point, and why there are three copies of it

`UsersService.provision({ candidate, source })` is the sequence: complete the candidate through
`model.completeInsert` → `beforeUserCreate` (rewrite or refuse) → re-validate a rewrite through
`model.insert` → `userStore.create` → `afterUserCreate`. It **opens no transaction of its own** and
it **publishes no `UserCreated`** — both stay with the caller, so a refusal or a failing
`afterUserCreate` aborts whatever transaction the caller holds, and the event is still published
after the commit as `Events.ts` requires. A rewrite going back through the *deployment's own*
`insert` variant is what stops a hook smuggling a row the schema would reject — the base model
alone would check half of it and wave the deployment's own columns through, leaving `UserStore`, a
seam somebody else may implement, as the only thing that could catch a `plan` outside its union.

**The candidate is completed before the hook, not after it.** `Passwords` builds its row with
`model.makeInsert`, but `Accounts` and the magic-link plugin are base-typed on purpose and build
theirs from the base fields alone; filling the deployment's columns in from the model's declared
defaults *first* is what makes `hooksOf`'s promise true on every source. Without it the same typed
policy would read `candidate.plan` as `"free"` on a sign-up and `undefined` on an OAuth or
magic-link sign-up, and derive whatever it derives from that. `test/fields/Hooks.test.ts`'s
`every source` block is the pin.

**A rewritten address is re-normalized.** `email` is a plain `Schema.String` and the stored column
is normalized by the discipline of every caller that writes it, so a hook answering with
`User@Example.com` would otherwise store a row that `findByEmail(normalizeEmail(…))` — which is
every read of a user by address — could never find again, while a second sign-up for the same
mailbox passed both the duplicate pre-check and the unique index.

`magic-link` calls `Users.provision`. `Passwords` and `Accounts` **reimplement the same sequence**,
in `provision` helpers of their own, and this is the one deviation from hooks.md worth recording:
`Users` reads `Passwords` (it re-authenticates a caller before deleting an account), so a dependency
the other way would close a cycle in the layer graph and `Auth.layer` would not build. The three
copies have to stay in step; each carries a comment saying so, and the cross-source suite in
`test/domain/Hooks.test.ts` is what fails when one of them drifts — one hook set, one trace, all
three sources.

`ProvisionSource` is what a hook branches on: `EmailPassword`, `OAuth` (carrying `providerId` and
the verified `OAuthUserInfo`, so one hook covers every provider), `MagicLink`, and
`Plugin { plugin }` for a plugin that provisions users of its own.

#### 13.3 Refusal, shaped by the endpoint

`PolicyRefused { code, detail? }` is a `403` and the **only** typed failure a hook may raise.
Anything else it throws or dies with is a defect and renders as an opaque `500`, which is the right
answer for a broken policy. Handlers never `serverFault` it: it is a caller error.

- **JSON endpoints** answer the typed error: `signUpEmail`, `signInEmail`, `signInSocial`,
  `linkSocial`, `changeEmail`, `deleteUser`, magic-link `exchange`.
- **Redirect-shaped completions** — the OAuth callback, magic-link `verify`, `deleteUserCallback` —
  encode it as `?error=policy_refused&code=<the hook's code>`, because the browser arrived by a
  top-level navigation and has to leave by one. One helper builds that URL for all three:
  `OriginCheck.policyRefusedTarget(config, errorURL, code)`, beside `withErrorCode`, so the shape
  cannot drift between them. The OAuth callback passes the flow's own `errorCallbackURL`, and so
  does magic-link `verify`: the payload is claimed before either hook is consulted, so
  `MagicLink.complete` still has that URL in hand and resolves a refusal into it exactly as it
  resolves `invalid_token` — `PolicyRefused` is a member of `VerifyError` and `errorCode` answers
  `policy_refused` for it, mirroring the OAuth flow's `CallbackError`. `deleteUserCallback` is the
  one that lands on `baseUrl`, and deliberately: the only URL that link carries is where to land
  once the account is *gone*, which is not a page to send somebody whose deletion was refused.
- **Sign-up's auto-session is the one refusal that does not undo anything.** The account and its
  credential are committed before `beforeSessionCreate` is asked, and `beforeUserCreate` has already
  said this person may have an account, so a refusal there answers exactly as `autoSignIn: false`
  already does: `200`, with `session: null`. It is logged at `Debug` so an operator is not left
  guessing between this and the two configuration switches. Deleting somebody who was accepted a
  moment earlier was rejected as the alternative.

`code` is authored by the deployment and shown to the caller verbatim — in a response body and in a
URL a browser is sent to. **It must carry no secret**, nothing derived from another person's data,
and nothing about the internals of the policy; it is a short stable classification a client branches
on (`"domain_not_allowed"`, `"banned"`). `detail` is under the same rule. This is stated in
`PolicyRefused`'s own JSDoc, which is where a hook author reads it.

#### 13.4 Breaking change: error channels

This is the one breaking surface of the feature. `PolicyRefused` joins the `AuthError` union
(`domain/Errors.ts`) and the error channel of every method that can now refuse — on
`UsersService`, `PasswordsService`, `AccountsService`, `OAuthFlowService` and `MagicLinkService` —
and the error array of the seven JSON endpoints above. A caller that exhaustively matched one of
those unions gains a case. Nothing else moved: no migration, no new table, no configuration key,
and `Auth.layer`'s type is character for character what it was (`test/fields/Fields.types.ts`).

#### 13.5 Composition

`AuthHooks` is a `Context.Reference<AuthHooksService>` whose default is `{}` — every hook absent —
so `Auth.layer` needs nothing provided to it and a deployment that installs no policy pays nothing,
in its layer graph or on any path. It is read when the services that consult it are **built**, so
hooks are provided *underneath* `Auth.layer` and cannot be swapped per request.

`combine(first, second)` is a monoid with `{}` as its identity: `beforeUserCreate` chains left to
right with each hook seeing what the one before it answered, the rest sequence, and the first
refusal short-circuits the remainder. A member neither side declared stays **absent** rather than
becoming a no-op function — "nobody installed a hook" and "somebody installed one that does nothing"
must not be the same value.

- `Hooks.layer(hooks)` installs a set, replacing what was there. An **application** uses it.
- `Hooks.append(hooks)` reads what is installed — the reference's default included — and combines
  after it. A **plugin** uses it, because it cannot know what else the deployment installed: an
  application's refusal short-circuits an appended plugin hook, and a plugin never silently disables
  an application's policy.
- `Hooks.hooksOf(model)` is the typed view: the same key string with `candidate`/`user` typed by the
  deployment's model, exactly as `userStoreOf` and `currentUserOf` are, and sound for the same
  reason — core reads the base-typed key and hands it a row that really does carry the extra
  columns, and re-validates any rewrite through the model. It needs **no cast**: it is another
  `Context.Reference` under the same key, so the cast list in REFACTOR §5 is unchanged at five.

`AuthTest.Settings.hooks` is the harness seam, provided under the deployment. A plugin layered over
a deployment is built separately, so a test that wants both halves to see one set provides it under
the whole composition — `test/domain/Hooks.test.ts`'s cross-source block is the worked example.

#### 13.6 Tests

`test/domain/Hooks.test.ts` — the kernel (`combine` ordering, first-refusal-wins, `{}` identity,
`append` over a consumer set and over the bare default, the `Layer.updateService`-over-a-default
checkpoint, the typed view sharing a slot), the choke point itself, the password source (rewrite,
veto, a failing `afterUserCreate` leaving no row, the `session: null` pin), the OAuth source through
`Accounts`, the timing-defence block over `countingHasher`, and the cross-source block: one
appended set, three sources, one trace. `test/oauth/Hooks.test.ts` and
`test/magic-link/Hooks.test.ts` — the redirect encodings and the typed twin. `test/http/Users.test.ts`
— change-email and delete vetoes at the HTTP layer, and a refused delete link that is still burnt.
`test/fields/Hooks.test.ts` — a typed set installed through `hooksOf(model)` reading `plan` and
writing `role` and `apiSecret`, the same set reading the same columns on the OAuth and magic-link
sources (the `every source` block), and a base-typed set answering with a `plan` outside the union,
refused on both sources with nothing stored. `test/fields/Fields.types.ts` and `test/client/AuthClient.types.ts`
— the candidate is `UserInsertOf<F>`, base and typed sets are interchangeable, and `PolicyRefused`
is in the client unions it should be in and no others.

### 14. Shared-shape pass: the four surface changes it makes

A de-duplication pass over the modules above — one derivation, one builder, one home per shape —
made four changes a reader of those sections would not predict. Everything else it touched is
internal. Behavior is unchanged except where (3) says otherwise.

1. **`AuthConfigService` gains `readonly trustedOriginSet: ReadonlySet<string>`.** The set of
   origins a request may claim is derived once, by `AuthConfig.make` from `baseUrl` and
   `trustedOrigins`, and stored on the config; `OriginCheck.trustedOrigins(config)` now reads that
   field instead of recomputing the set per request. `OriginCheck.trustedOriginSet` remains the
   exported derivation for a caller building the set from its own inputs. Same origins, same
   comparison — the config is immutable, so the two could not disagree.

2. **`sessionCookieSecurity` moved from `MiddlewareLive` to `Cookies`.** Its public path is now
   `AuthCookies.sessionCookieSecurity(config)`, beside `sessionCookieOptions` and
   `expiredSessionCookieOptions`, which is where the rest of the session cookie's attributes are
   already decided; `MiddlewareLive` imports it. The `HttpApiSecurity.ApiKey` it builds is
   unchanged, and so is every cookie the middleware sets or clears.

3. **`RateLimits.layerStore(options?)` is the default `RateLimiterStore`, and it evicts.** The
   store counts fixed windows in process-local memory exactly as `RateLimiter.layerStoreMemory`
   does, and additionally deletes an expired window on a sweep that runs for as long as the layer's
   scope (`options.sweepInterval`, one minute by default — no shorter than either bucket this
   library configures). `RateLimits.layer` provides it in place of `RateLimiter.layerStoreMemory`.
   This is the one **sanctioned behavior change** of the pass, and it is a security fix: a bucket
   key embeds the client address, taken by default from a header the client can forge, and the
   upstream store never deletes a key — so an unauthenticated caller with a fresh spoofed address
   per request grows the map for the life of the process, unbounded. The sweep bounds the store's
   *size*, never a live counter: a caller still spending its allowance keeps its window, so no
   limit is loosened. A deployment wanting a shared store still swaps it —
   `RateLimiter.layer.pipe(Layer.provide(myStore))`.

4. **`OriginCheck.redirectFailure` / `RedirectFailure<E>` are the shared redirect-shaped failure.**
   The OAuth callback and magic link both answer a failed completion by redirecting, and both built
   the same `{ _tag: "Failure", error, redirectTo, code }` value from the same parts: the flow's
   own closed-set `errorCode`, `resolveUrl` for an absent or untrusted `errorURL`, and the extra
   `&code=` a `PolicyRefused` carries beside this library's classification (§13). That construction
   now lives once, as `redirectFailure(config, errorCode)`, and each flow supplies only its
   `errorCode`. Both flows' redirect targets and query strings are byte-identical to what they
   were.

### 15. The provider seam: one OIDC block, one escape hatch

`OAuthProviderConfig` is the one type every provider in this library and every provider a consumer
writes is described by, and it had grown six optional top-level fields that were only meaningful
together and one shape it could not describe at all. This amendment settles both, and supersedes the
`OAuthProviderConfig` sketch in the OAuth section above.

1. **The six OIDC fields became one `oidc` block, and its key source is a union.** `issuer`,
   `issuerOf`, `jwks`, `jwksUrl`, `idTokenAudience` and `algorithms` are gone from the top level;
   what replaces them is `oidc?: { issuer, issuerOf?, keys, audience?, algorithms? }`, where
   `keys` is `{ jwksUrl: string } | { jwks: KeyResolver }`. `Provider.isOidc` is the guard, and it
   narrows `oidc` to **required**, so a caller past it reads the issuer and the key source without a
   second check. `providerIssuer(provider)` is unchanged: `oidc.issuer` when there is a block, the
   synthetic `local:oauth:<id>` when there is not.

   The presence of the block is what it always was — the thing that puts a provider on the OIDC path
   and makes an `id_token` demanded rather than tolerated. What is new is that **the union is the
   fail-closed rule**, not a runtime branch enforcing it. A hand-written provider with an issuer and
   no key source at all used to be buildable, and `Flow.withIdToken` carried the arm that refused it
   at callback time with `IdTokenInvalid`. That configuration is now unwritable — `keys` is
   required, and there is no third arm of the union — so the arm is deleted and the guarantee is a
   type rather than a test: the refusal moved from callback time to compile time. Nothing about
   discovery changed; §11.2 (18)'s `KeysMissing` is a rule about a *document*, and `OidcDiscovery`
   reported it at construction before this wave and reports it there still.

   The other fail-closed behaviours are untouched: a missing `id_token`, an unreadable JWKS, a
   wrong `iss`, `aud`, `exp` or `nonce` all still fail, and a JWKS that cannot be fetched is still
   never "skip verification".

   Two consequences worth stating. **A pinned key set is now an irreversible choice at construction
   rather than a runtime preference** — the old flow read `jwks` first and fell back to `jwksUrl`,
   so the precedence is unchanged, but the built provider no longer carries an unused URL, and key
   rotation (`freshKeys`) applies only on the `jwksUrl` arm, because pinned keys are pinned. And
   **`Microsoft`'s synthetic issuer for `common` / `organizations` / `consumers` stays**, as §11.2
   (16) describes it: the block's `issuer` is a required `string`, so those three tenants still need
   a name there, and `issuerOf` is still what a token is actually compared against. What the block
   buys is that the string is now visibly inert rather than apparently believed. §11.2 (14)'s rule
   is unchanged in substance and reads `Apple`'s `oidc.audience`.

2. **`exchange` is the escape hatch for the exchange the generic runner cannot describe.** A
   provider may declare
   `exchange?: (options: { code, codeVerifier, redirectUri, fallback }) => Effect<OAuthTokens, OAuthProviderError, HttpClient>`.
   Absent — the ordinary case, and every provider this library ships — the flow performs the
   exchange itself, byte for byte as before. Present, it owns the exchange: nothing else posts the
   code.

   `fallback` is the point of the design. It is the generic token request **already built for these
   exact inputs**, so an override that only decorates the default — one extra header, some
   post-processing of the tokens — wraps it rather than reimplementing an OAuth2 token request. That
   keeps two things the flow must not hand across the seam on the flow's side of it: client-secret
   resolution, including the per-request ES256 minting an Apple client needs, and
   `reservedTokenParams` filtering. An override sees a code, a verifier, a redirect URI and an
   effect; it never sees the secret. **Decorate, don't reimplement** — an implementation that
   ignores `fallback` and builds its own request owns everything the flow was doing for it, and that
   is the price of the case where the provider's exchange genuinely is not an OAuth2 token request.

   `fallback` has no `R`. The flow provides its own redirect-refusing `HttpClient` into it before
   handing it over, and discharges the override's own `HttpClient` requirement the same way — the
   same client `userInfo` gets, so an override cannot be talked into following a redirect to an
   internal address.

   An override that bypasses `fallback` and drives the `HttpClient` itself is not wrapped in
   `resilient`, so nothing inside it bounds a provider that accepts a connection and never answers.
   The flow bounds it from outside instead: `Provider.exchangeDeadline` (30 s) sits above the whole
   exchange step — override and default alike — and reports a `TimeoutError` as
   `OAuthProviderError("ProviderUnavailable")`, exactly as `userInfoDeadline` does one step later.
   The two deadlines are the same rule applied to the two steps a provider can take over, and for
   the same reason: a bound an implementation can opt out of is not a bound.

3. **Two providers registered under one id is a construction defect.** `Provider.makeRegistry`
   throws on a duplicate id rather than letting the last registration win. A duplicate is a
   deployment that cannot be served coherently — one of the two would silently never receive a
   callback, because an id is the `providerId` of `POST /auth/sign-in/social`, the last segment of
   the callback path and the `trustedProviders` entry all at once — so it is refused loudly at
   start-up instead of merged. `OAuthProviders.layer(providers)` is `Layer.succeed` over
   `makeRegistry`, so the throw happens where the layer *value* is constructed, at the
   `OAuthProviders.layer([...])` call site, rather than inside `Layer.build`. That is still a
   start-up failure at the composition site; making it a true build-time defect would need
   `Layer.sync`, and is not worth a behaviour change on its own.

   The null-prototyped dictionary and `Object.hasOwn` lookup are unchanged: ids arrive from request
   paths, so a request for the provider `"__proto__"` must miss rather than return a function.

4. **Resilience doctrine: the flow owns policy, the helpers own mechanics.** This wave added
   `Provider.userInfoDeadline` and `Provider.exchangeDeadline` (30 s each) and the flow enforces
   them around the two steps a provider can take over — a provider's *entire* `userInfo`
   invocation, and the whole exchange including an `exchange` override — mapping a `TimeoutError`
   to the existing `OAuthProviderError("ProviderUnavailable")` — no new reason, so nothing new
   reaches the browser through `errorCode`'s closed set.

   The split is deliberate and is the rule for anything added here later. `Provider.fetchJson`
   bounds *one* request with `providerRequestTimeout` and retries transport failures, because that
   is what one request needs; the deadlines sit above the whole provider call and answer a
   different question — how long a callback fiber may be held at all. GitHub asking two endpoints in
   sequence, each within its own timeout, is still bounded by the one deadline. And a deadline
   lives in the flow rather than in the helper precisely because a provider implementation is free
   to bypass `fetchJson` and use the `HttpClient` directly: a bound a provider can opt out of is not
   a bound. All the sleeps are on the Effect clock, so a test moves them with `TestClock`.

### 16. Security hardening pass (post-audit)

A five-reviewer audit of v2 raised three findings the fixes below settle. Each changes an
observable contract or a configuration rule, so it is recorded here rather than left silent. No
endpoint, wire shape or service key moved; the OAuth callback gains one precondition, the session
row gains one persisted field, and one config invariant is corrected.

1. **The OAuth `state` is now bound to the browser that started the flow.** The single-use
   `DELETE … RETURNING` consume stops forgery of an unissued state and replay of a spent one, but
   not an attacker who *legitimately* obtained a `state` (by starting a flow with their own
   provider account) and then lured a victim's browser to the callback — a login-CSRF that would
   silently sign the victim into the attacker's account, or, on a link flow, attach the victim's
   identity to the attacker's. The fix is the standard binding: `signInSocial` and `linkSocial`
   set a short-lived, `HttpOnly` cookie (`effect_auth.oauth_state`) holding the raw `state`;
   `oauthCallback` clears the cookie on **every** exit (the `unknown_provider` early return
   included) and requires the incoming `state` query parameter to be present and equal that cookie
   **before** it consumes the state row. A callback whose browser
   holds no matching cookie redirects with the same closed-set `?error=state_mismatch` an unissued
   state gets, to `baseUrl` (the caller's `errorURL` lives in a state row that has not been
   consumed at that point). The browser token is the raw `state` itself, carried in a cookie — no
   new `verifications` column, and the state payload is unchanged.

   Two attributes were tightened past the first cut of this fix, both driven by review:

   - **Prefix `__Host-`, not `__Secure-`, on TLS.** `__Secure-` binds a cookie to HTTPS but not to
     a host, so a page on a sibling subdomain can set a `Domain`-scoped
     `__Secure-effect_auth.oauth_state` valued at a `state` it obtained, and that cookie rides the
     callback and passes the equality check. `__Host-` forbids `Domain` and pins the cookie to the
     exact host that set it, closing the tossing vector. The state cookie is set and read on the
     same host and never legitimately carries a `Domain`, so it loses nothing. `__Host-` mandates
     `Secure`, `Path=/` and no `Domain`; the cookie's options honour all three — `Path` is fixed to
     `/` and `Domain` omitted regardless of `cookie.path`/`cookie.domain`. On a plain-HTTP
     deployment, where `Secure` cannot hold, the name is the un-prefixed `effect_auth.oauth_state`.
     This applies to the oauth_state cookie **only**; the session cookie's prefix is unchanged.

   - **`SameSite` follows `cookie.sameSite`, capped away from `Strict`.** It is `None` when the
     deployment configures `cookie.sameSite: "none"` (a frontend on a different site than the auth
     server, validated with `secure`) and `Lax` otherwise — never `Strict`. A `None` deployment
     makes `signInSocial` a cross-site request, and a browser rejects a `SameSite=Lax` `Set-Cookie`
     on a cross-site subresource response, so a hard-coded `Lax` left the cookie unstored and every
     callback failing `state_mismatch`. The binding's security is the `HttpOnly` value-equality
     check at the callback, not `Lax`, so following the deployment's `sameSite` does not reopen
     login-CSRF; `Strict` stays excluded because the callback is a cross-site top-level GET a
     `Strict` cookie would not ride.

2. **A `rememberMe: false` session is never silently promoted to persistent.** The rolling refresh
   re-set the session cookie *with* a `Max-Age` because the row recorded nothing about the
   remember-me choice. The `sessions` table now carries a `remember_me` boolean (`Sessions.create`
   persists it from its existing `{ rememberMe }` option, defaulting to `true`; `verify`/`touch`
   return it), and the middleware passes `persistent = session.rememberMe` to `setSessionCookie` on
   refresh, so a non-persistent session is re-sent as a browser-session cookie in **every**
   configuration.

   The fix is on the row, deliberately, and **not** in `AuthConfig.validate`. The existing bound —
   `updateAge` no longer than `rememberMeDisabledExpiresIn`, alongside `updateAge` shorter than
   `expiresIn` — is unchanged and is *not* a promotion guard: it says the refresh window must fit
   inside the shortest session a deployment mints, so the rolling refresh applies to that session
   too. It therefore guarantees a `rememberMe: false` session becomes refresh-due before it
   expires, which is exactly the window the promotion used to occur in — the triggering condition
   is `updateAge` **shorter** than `rememberMeDisabledExpiresIn`, and both the old comment at
   `MiddlewareLive.ts` and the review that raised this stated it backwards. Inverting the bound to
   forbid that relationship was considered and rejected: with the column in place it defends
   against nothing, it turns currently-valid deployments (any `updateAge` below one day) into
   start-up failures, and it would make a `rememberMe: false` session unrefreshable — destroying
   the "rolls per window while staying short" behaviour that `Sessions.grantedLifetime` is written
   to provide and that `test/domain/Sessions.test.ts` pins.

   One wire-visible knock-on: `rememberMe` is a plain field on `Session`, so it appears in
   `Session.json` — on `GET /session` and `GET /sessions`, and inside the session cookie cache's
   signed envelope. Snapshots written before this change no longer decode, which is a cache miss
   and safe by design (§12.4).

3. **Revoking your own session clears its cookies, and the revoke endpoints read the row.**
   `POST /revoke-session` against the caller's *own* session now calls `clearSessionCookies` (as
   `revoke-sessions` already did), or the cookie cache would keep the browser authenticated behind
   its snapshot for up to `cookieCache.maxAge` after the row was deleted. `revokeSession` and
   `revokeOtherSessions` are additionally annotated `AuthoritativeSession`, so a session revoked in
   another browser cannot drive a revocation through the cache within the lag; both handlers read
   the session row in-handler regardless, so the annotation costs them nothing. The eight existing
   `AuthoritativeSession` annotations are unchanged.

### 17. Deterministic service keys

Every `Context.Service` key in the package is now module-qualified. The convention the
`@effect/tsgo` `deterministic-keys` rule enforces, and the one this package writes by hand:

```
"<package>/<module path>/<Identifier>"
```

where the module path is the source file's path under `src/` (or, for a test-local service,
under the repo root) with its extension dropped, and `<Identifier>` is the declared name. The
`<Identifier>` segment is elided when it would only repeat the file name, which is why a
one-service module reads `"effect-auth/crypto/Token"` rather than
`"effect-auth/crypto/Token/Token"`:

```ts
// src/domain/Stores.ts
export class UserStore extends Context.Service<UserStore, UserStoreService>()("effect-auth/domain/Stores/UserStore") {}

// src/crypto/Token.ts
export class Token extends Context.Service<Token, TokenService>()("effect-auth/crypto/Token") {}
```

Two consequences worth stating:

1. **A typed view must repeat its base key verbatim.** The `…Of(model)` helpers of §8 —
   `userStoreOf`, `sessionStoreOf`, `usersOf`, `sessionsOf`, `passwordsOf`, `sessionCacheOf`,
   `currentUserOf` — exist precisely to read the *same* context slot through a narrower shape,
   so each restates the qualified key of the class it views. A helper whose key drifts from its
   class silently becomes a second, unprovided service. The lint rule does not see these call
   sites; they are kept in step by hand.

2. **These keys are process-local identity, not wire format.** A service key is never
   serialized: it names a slot in a `Context`, nothing more. It is emphatically *not* a tagged
   error's `_tag`, which is a wire value — `{"_tag": "InvalidCredentials"}` in a JSON error body
   — and is frozen. A `Schema.TaggedError` therefore declares two strings, and only the first
   (the schema identifier, which OpenAPI component names derive from) is subject to this
   convention.

`Context.Reference` keys are outside the rule's scope and were left as declared. There are three
of them, all unqualified: `"effect-auth/AuthoritativeSession"` (`src/http/Middleware.ts`),
`"effect-auth/AuthHooks"` (`src/domain/Hooks.ts`, restated by `hooksOf`) and
`"effect-auth/UserModel"` (`src/domain/Schema.ts`).

**The rule itself is now off** (Amendment 18). The 26 module-qualified keys in `src/` and the 3 in
`test/` stay exactly as they are — they are already written, already reviewed, and a key rename is
never free — and the `effect-auth/<module path>/<Identifier>` scheme above remains the convention
for any key added from here on. It is maintained by hand rather than enforced, which is the same
footing the typed-view helpers were always on: `userStoreOf` and its siblings restate the literal
from a *call site*, and `deterministic-keys` never saw those, so the only thing the rule was ever
checking was the class declaration it was already obvious at. Consequence 1 above therefore now
describes the whole file, not just the `…Of` helpers.

### 18. Lint calibration (2026-09-01)

Amendment 17's wave turned all 96 rules `@effect/tsgo@0.38.0` ships to `error` at once. An audit of
what that cost found several rules doing ergonomic damage for no safety gain, and this amendment
records the dial-back. The reference point is Effect's own `recommended` preset
(`node_modules/@effect/tsgo/oxlint-presets/recommended.json`): it calibrates 82 of the 96 rules —
**13 at error, 69 at warn** — and excludes 14 outright, all of which this package had at error.
Five of the excluded 14 are the ones that did the most damage here: `missing-pipeable-signature`,
`new-schema-class`, `deterministic-keys`, `strict-boolean-expressions` and `strict-effect-provide`.
We still run stricter than the preset — `new-schema-class` and `strict-boolean-expressions` stay
at error, and 88 further Effect rules stay at error too (90 of 96) — but on six Effect rules (two
off, four warned), plus `typescript/consistent-return` from the core set, the preset turned out to
be right, and on `strict-effect-provide` it is right for tests and wrong for `src/`.

**Off.** Three rules, each because it changed shipped code rather than finding a defect:

- `effecttsgo/missing-pipeable-signature` demanded a data-last `dual()` overload on every exported
  combinator. Satisfying it produced **69 `dual()` sites in `src/`** (73 counting two test helpers)
  and **not one data-last caller** anywhere in the library, its tests or `examples/basic` — every
  one was dead weight paid for in a doubled type signature. Worse, fifteen of them (seventeen
  counting the two test helpers) could not use an arity and needed a *runtime dispatch
  predicate*, including `AuthHandlers.layer` — the single
  most-called entry point in the package — where `dual((args) => HttpApi.isHttpApi(args[0]), …)`
  put a value-shape test in front of `layer(api)`. `MockProvider.json` acquired the sharpest edge:
  its predicate was `typeof args[0] !== "number"`, so a bare numeric *body* had to be written
  `json(200)(404)` — a footgun the code had to apologise for in a comment. `grep -rn "dual(" src
  test` is now empty.
- `typescript/consistent-return` added **four `return undefined`s** and, in
  `Middleware.requireFresh`, a comment apologising for one. It also collides with
  `effecttsgo/missing-return-yield-star`, which is at error and requires the failing branch of a
  generator to be `return yield*`: once one path is valued, the rule demands the other be too, so
  the fix is always the noisier of two spellings the type system already distinguishes. It found no
  defect in the tree.
- `effecttsgo/deterministic-keys` couples a runtime `Context.Service` key to a file path, which
  means a file move is an invisible key rename. The keys it prompted are kept (Amendment 17); the
  standing rule goes, so a future key is chosen for the wire and the reader rather than for the
  linter.

**Warn.** Four rules the preset also warns on, kept as a prompt to look rather than a gate:
`async-function` (an `async` function at a genuine platform boundary — jose, WebCrypto, the PGlite
driver — is the correct code), `global-date` and `global-date-in-effect` (`Date` in a pure helper,
a type-level default or a doc example is not a clock read), and
`catch-conditional-refail-to-catch-if` (the `catchIf` rewrite is usually a readability preference;
`AuthHandlers.dieOn` keeps it deliberately, seven explicit type arguments and all, because
`catchIf` re-fails the *original* Cause on the pass-through branch where `Effect.catch` +
`Effect.fail` would build a fresh one and drop its annotations).

**Tests and the test kit** (`test/**`, `src/testing/**`) turn thirteen rules off in an override,
because a test is an entry point, not library code — several of the rules say so in their own
message. The decisive measurement: of the **90** `strict-effect-provide` findings in the pre-wave
tree, **88 were in `test/`**, and satisfying them cost isolation. Three OAuth suites had their
per-test mock servers collapsed into shared module-level ones — `Discovery.test.ts` 7 → 2,
`Providers.test.ts` 7 → 4, `Provider.test.ts` 3 → 1 — which is exactly the coupling
`describe.sequential` exists to contain. Separately, `prefer-schema-over-json` rewrote the two OAuth
token-leak assertions from `JSON.stringify(failure)` to `Inspectable.toStringUnknown(failure)`,
weakening a check whose whole point is that it serializes the *entire* value so a leak anywhere in
it is caught. Both are reverted; the override is what keeps them reverted.

**What stays at error, and earned it.** `effecttsgo/unnecessary-fail-yieldable-error` removed **73**
`yield* Effect.fail(…)` wrappers in `src/` (75 → 2), which is a real simplification of every error
path in the library. `typescript/no-unnecessary-type-arguments` and
`typescript/no-unsafe-type-assertion` both fire under this config and both find things prose cannot:
the second is what now machine-enforces REFACTOR.md §5, with exactly five suppressions in `src/`.
`effecttsgo/new-schema-class` also stays, so `X.make({})` is the constructor everywhere.

**A correction to the record on `Cookies.ts`.** The wave's `global-date` change there replaced
`new Date(0)` in `expiredSessionCookieOptions` and `expiredOAuthStateCookieOptions` with a `DateTime`
detour, described at the time as removing a reachable wall clock. It was not: `new Date(0)` is the
Unix epoch, a constant, and it is what a cookie expiry *must* be to delete a cookie. There was no
wall-clock defect. The genuinely clock-dependent path in this area,
`MiddlewareLive.remainingLifetime`, was already on the injected clock (`DateTime.now`) and was never
touched. Both sites are back to `new Date(0)` with a one-line
`// oxlint-disable-next-line effecttsgo/global-date -- epoch constant, not a clock read`.

### 19. Phase 1 — human authentication

The wave `phase1.md` specifies: a session that records *how* it was authenticated, one choke point
every sign-in goes through, a challenge primitive, and seven plugins built on the seams those three
create. It is the largest change since §8. This amendment does not restate `phase1.md` — read Part D
there for the locked decisions — it records what was built, what the build learned that the plan did
not know, and every place the result is not what a reader of §§8–18 would predict.

Magic link is gone. §10 describes a module that no longer exists; **email-otp supersedes it**, and
`src/email-otp/` is the reference plugin §9 points at. Everything §10 established survives the move
and is restated in 19.9 where it changed.

#### 19.1 The session records how it was authenticated

`sessions` gains three columns (`0006_session_assurance`): `authenticated_at` (no `DEFAULT` — only
the writer knows when a person actually authenticated, and any constant would be a lie; added
nullable, backfilled from `created_at`, then `SET NOT NULL` on PostgreSQL), `aal` (`DEFAULT 'aal1'`)
and `methods` (`DEFAULT '[]'`). Consumers merging `Migrations.migrations` number their own above
`0006`, and any hand-written `INSERT INTO sessions` must now state `authenticated_at`.

`Assurance.deriveAal` is the whole derivation, and it is deliberately small: entries with
`factor: "none"` are struck out first; nothing left is `aal0`; one entry that reports the WebAuthn
UV bit is `aal2` on its own; two or more *distinct* `factor` values are `aal2`; anything else is
`aal1`. Distinctness is what stops a TOTP code and a mailed code adding up to `aal2` — they are both
possession, and two of the same kind is one kind. **`aal3` is never derived**, and `amrOf` never
emits `hwk`: both would be claims about hardware this library does not verify attestation for.

Three consequences that surprised the build and are worth stating plainly:

1. **Possession + possession is `aal1`.** A sign-in whose first factor is OAuth, email-otp, SMS,
   One Tap or a passkey the authenticator did not verify a person for, completed with a TOTP or a
   recovery code, lands at `aal1` — correctly. Two things you *have* are not two factors. Anything
   that reads a level to decide whether a second factor was answered is therefore wrong, and 19.6
   is where that bit the two-factor plugin twice.
2. **`Session.methods` is a JSON string on the wire**, not a nested array. `SessionCache` encodes a
   snapshot through `Session.json` and decodes it back through the *stored* variant, so a `json`
   variant that encoded to a real array would make every cache read fail to decode and silently
   disable the cookie cache. The `accounts.scope` column is the precedent. All three columns are
   json-visible on purpose (§12.1); `tokenHash` stays `Model.Sensitive`.
3. **The insert defaults and the mint defaults disagree, deliberately.** The model's insert defaults
   are `aal1` / `[]` / the insert clock — what a row written before this wave should read as. The
   mint defaults to `[]` / `deriveAal([]) === "aal0"` / now: a mint that recorded no evidence is
   `aal0`, which fails every policy that asks for a level. The model's default is history; the
   service's default is honesty.

`Sessions.create` is renamed **`createUnchecked`**, and the name is the documentation. It writes a
row and consults nothing — no hook, no pipeline, no event — so a plugin that calls it is a sign-in
door with no policy on it, which is exactly the bypass 19.2 exists to make unrepresentable.
`SignIn.complete` is its only sanctioned caller, and a test asserts that `src/` calls it in exactly
one place.

`Sessions.elevate(session, evidence)` appends to the log, re-derives the level, re-stamps
`authenticated_at` and rotates `token_hash` **together**, under a lock on the row, in one
transaction with the read that produced it. The rotation is part of it so a token captured at `aal1`
cannot inherit `aal2`; the session id does not change, so open tabs and the session list survive.

**The read is the point, and the store's signature is shaped to force it.** `SessionStore.elevate`
takes an `append` callback rather than a finished array, and hands it the log *as stored*. A caller
holds a `Session` *value*, and that value can be stale — it may have come from a cookie-cache
snapshot on an endpoint that did not ask for the row, or from a request that raced another
elevation. Writing `caller.methods + evidence` would silently drop whatever the row had learned in
between (the password entry an earlier `reauthenticate` recorded, the factor a parallel request just
proved) and the level, being derived from the log, would move the wrong way. `append` runs inside
the transaction under the row lock, so it must be pure and must not do IO; it is where `deriveAal`
is called, which keeps the one function that computes a level in the domain rather than in a store
implementation. `None` means the session was concurrently revoked.

**One precision on that rotation.** "The old token stops resolving the instant the new one starts"
is true *of the row*. A cookie-cache snapshot bound to the old token keeps serving endpoints that
carry neither `RequireAssurance` nor `AuthoritativeSession` until the snapshot expires — the same
class of lag §12.4 already records for revocation, and no assurance is gained by it, because every
endpoint that states a policy reads the row. This is why "every step-up and factor-management
endpoint carries `AuthoritativeSession`" is a rule and not a preference.

`Sessions.touch` — the rolling refresh — moves `expires_at` and provably never
`authenticated_at`, `aal` or `methods`.

#### 19.2 One choke point: `SignIn.complete` and the `SignInPipeline`

Every path that mints a session goes through `SignIn.complete`: password sign-up and sign-in, the
OAuth callback, email-otp, username, anonymous, phone, One Tap and the passkey ceremony. It runs
`beforeSessionCreate`, then consults the `SignInPipeline`, then — on `Proceed` — runs
`beforeSessionMint`, then mints.

**There are two hook points, and the pipeline is what put them there.** `AuthHooks` gained
`beforeSessionMint` in this wave, and the split is the whole reason:

- `beforeSessionCreate` asks *may this person sign in at all*. It runs first, so a deployment that
  has withdrawn access refuses before a factor plugin issues a pending row, sends an SMS or writes
  anything on that person's behalf.
- `beforeSessionMint` asks *what has to happen as this session is minted*. A second factor may still
  be owed when the first runs, and a challenged sign-in mints nothing — so a merge, a migration of
  somebody's data, or a `DELETE` of the account being merged away must run here or they run for a
  sign-in that never completed.

The anonymous plugin's merge hangs on the second, and that is not a preference. Deleting the visitor
at the earlier point deletes them even when the person then abandons the second-factor prompt,
mistypes their codes, or is refused — leaving a browser holding a dead cookie for an account that no
longer exists and signed in as nobody. A `PolicyRefused` from either aborts the mint; note that the
credential the caller presented is already spent by then, because it was checked before either hook
ran, so refuse there only for something the caller cannot retry past. Neither hook runs inside the
transaction that writes the session row — `SignIn` holds no transaction runner — so a hook that must
be atomic with something opens its own, as the anonymous plugin does.

`SignInPipeline` is a `Context.Reference` monoid on the `AuthHooks` pattern: `combine` gives the
first `Challenge` the decision and never enters the decider behind it, so two factor plugins cannot
both write a pending row for one ceremony; `PolicyRefused` short-circuits identically; `{}` is a
true identity, which keeps "no decider" distinguishable from "a decider that always proceeds".

Because the pipeline is consulted inside `complete`, **there is no route list to forget an entry
from**. That is the entire point: the prior art this is modelled on gated three named sign-in paths
and let a TOTP user in through the fourth with no second factor at all.

#### 19.3 A pending authentication is not a session

**A `Challenge` mints nothing** — no session row, no token, no `SignedIn` event. The pending state
is whatever the decider issued: a single-use `Verifications` row carrying the stamped first-factor
evidence, the interrupted sign-in's `rememberMe` and its original method, addressed by a token that
rides only `__Host-effect_auth.pending`.

This is not a stylistic choice. A `sessions` row is a working credential everywhere in this library:
`Sessions.verify` accepts it, the middleware admits it, the cookie cache will snapshot it. One that
had cleared only the first factor would be a total bypass of every endpoint that forgot to check its
level — and "every endpoint remembers to check" is exactly the property this library declines to
depend on. Half-authenticated state therefore lives somewhere that cannot authenticate anything.

The pending token is never in a response body, and a response that carries the pending cookie
carries **no** session cookie. Both halves are asserted by reading the response's own `Set-Cookie`
rather than the jar.

#### 19.4 The two-status success union — and what the spike found

`POST /auth/sign-in/email` answers `SessionWithUser` on **200** or `MfaRequired` on **202**. A
half-hour spike established that rc.112 supports this properly, and it is used rather than
worked around:

- `HttpApiEndpoint.make`'s `Success` accepts an array; `validateSuccessResponse` refuses two members
  only when they share a status *and* a content type.
- Server side, `HttpApiBuilder.makeSuccessSchema` builds a union of response encoders, so the member
  is selected by which schema encodes — the two are disjoint (`MfaRequired` has `_tag`,
  `SessionWithUser` has `session`/`user`).
- Client side, `HttpApiClient` builds its decode map from status, and the endpoint's success type is
  a real TypeScript union that narrows on `"_tag" in result`.

A deployment with no factor plugin never produces the 202, so its wire is byte-identical to 0.1.0's.
`POST /auth/phone/sign-in/verify`, `POST /auth/username/sign-in`, `POST /auth/email-otp/verify` and
`POST /auth/passkeys/authenticate/verify` all answer the same union.

**A security middleware may not raise a non-`Unauthorized` error, and this is a standing
constraint.** `HttpApiBuilder`'s security loop runs the middleware once per declared scheme and, on
a failure, records it and tries the *next* transport, returning the last one's failure. `bearer` is
declared last and answers `Unauthorized` for the empty credential a cookie request carries, so a
`StepUpRequired` raised on the cookie transport was silently replaced by a 401 — observed, not
theorised. `MiddlewareLive.stepUpResponse` therefore encodes the refusal and returns a 403
`HttpServerResponse` as the middleware's *success*, which stops the loop. Every future guard living
inside `Authenticated` must answer with a response or move into the handler.

#### 19.5 `StepUpRequired`, `RequireAssurance`, and what "fresh" now means

`SessionNotFresh` is deleted. `StepUpRequired` (403, `{ required: AssurancePolicyJson, current:
{ aal, authenticatedAt, available } }`) replaces it and is declared on the `Authenticated`
middleware, so it appears on **every** authenticated endpoint's union and OpenAPI 403 — an
annotation is erased from the endpoint's type and the error has nowhere else to live. `InvalidCode`
(401) is added: one indistinguishable answer for a code that is wrong, expired, replayed,
cross-purpose or out of budget.

`requireFresh` is gone, and with it the duplicated freshness rule that lived in both `Sessions` and
`Middleware`. Freshness is now one member of one policy: `{ maxAge }` measured as
`now − authenticatedAt`, which is what "fresh" always meant and never quite was.

`AssurancePolicy` members are **conjunctive**, evaluated once in `Sessions.meetsAssurance`:
`allowRecovery: false` strikes `recoveryCode` entries out of the log *first*, so one filter serves
both the level and the method list; `aal` compares against `deriveAal` of what is left, on the
frozen ordering `aal0 < aal1 < aal2`; `maxAge` measures from `authenticatedAt`; `methods` is
satisfied by any one live entry whose name is listed. A policy that states nothing admits every
session. `current.aal` reports the session's *stored* level — what it has — while the comparison
uses the level *under this policy*.

`RequireAssurance` is an endpoint annotation (`Context.Reference<AssurancePolicy | undefined>`),
read in `MiddlewareLive` as `AuthoritativeSession` is. An absent `maxAge` resolves to
`assurance.stepUpWindow` (12 h) for a policy naming `aal2` and to `session.freshAge` (1 day)
otherwise; a stated one is taken literally, `Duration.infinity` included. **An annotated endpoint is
never served from the cookie cache** — a snapshot records the level a session held when it was
written, so an elevation since would be invisible and a revocation could be admitted.

`current.available` is the distinct `type`s of the `Authenticators` summaries that can sign in or
serve as a second factor. A deployment with no factor plugin answers `[]`, which is honest about the
seam and not about the account: `POST /auth/reauthenticate` is still open to anybody with a
password.

#### 19.6 A level is not evidence that a factor was answered

Two defects in the two-factor plugin, found in review, both from asking `deriveAal` a question it
does not answer. They are recorded together because they are one mistake.

1. **The decider's idempotence test.** It short-circuited on `deriveAal(evidence) === "aal2"`, which
   is true for a password sign-in completed with TOTP (knowledge + possession) and **false** for
   every possession-only first factor completed the same way (19.1). So a TOTP-enrolled user signing
   in through OAuth, email-otp, SMS, One Tap or a UV=0 passkey was challenged, answered correctly,
   and was challenged *again* on completion — which `verify` has no shape for, so it failed
   `PolicyRefused("mfa_required")` with the pending row spent and the code burned. Every
   non-password sign-in path was a lockout. The test is now "is one of *this plugin's own* factors
   already on the evidence", which is the question that was always meant.
2. **The factor-management endpoints.** `totp/disable` and `recovery/regenerate` required
   `{ aal: "aal2" }`, which a possession-only account can never reach: no sequence of calls this
   library serves would satisfy it, so such an account could enrol an authenticator app and then
   never disable it. They now carry `TwoFactor.provedSecondFactor` — `{ methods: ["totp",
   "recoveryCode"] }` — which says what the endpoint means (*prove you still hold the thing you are
   about to remove*), says it for every account shape, and is no weaker against the threat the guard
   exists for. It states no `maxAge` and so resolves against `session.freshAge`;
   `allowRecovery` is left unstated on purpose, because somebody whose authenticator is gone is
   exactly who needs to disable the enrolment.

**The general rule this leaves:** a level answers *how strong is this session*. It never answers
*was this particular factor answered*. Name the method.

#### 19.7 Challenges: short codes without a table

`Challenges` layers short codes over `Verifications` and adds no table. The row's secret is a
high-entropy **handle** the guesser must hold; the payload carries an `Hmac`-peppered `codeHash`
(domain-separated by `codeHashContext = "effect-auth/challenge-code/v1\n"`, which is part of the
stored format) and `attemptsLeft`. `verifyCode` claims the row atomically, compares in the storage
domain, and on a mismatch re-issues the *same* handle with one attempt fewer and what is left of the
original lifetime — so a typo costs an attempt and never the ceremony, and guessing cannot extend
the window. At zero nothing is written back, so an exhausted handle names nothing.

The pepper is not decoration: `Hmac` is a published service, so without a domain separator a plugin
signing caller-chosen bytes would be an oracle producing valid code hashes for all 10⁶ codes. Same
discipline as `SessionCache.macContext`.

Three properties fall out and are pinned by test: a fault between the claim and the comparison
restores the budget untouched; a budget that will not decode reads as exhausted; and the losers of
the atomic claim never charge an attempt, so N simultaneous wrong guesses spend at most N.

**A purpose shared between `Challenges` and `Verifications` must declare a payload schema.** A
payload-less purpose leaves a challenge row redeemable as an ordinary link token. With one, a handle
presented to `Verifications.claim` consumes the row and then fails payload decode — it burns itself
and reveals nothing, and a link token presented to `verifyCode` fails the same way.

**A budget key is never a value the caller chose.** The phone plugin's cross-challenge counter was
keyed on the number decoded out of the caller's *own* handle cookie, so ten forged handles naming a
stranger's number locked that number out of answering its own code — a denial of service anyone
could run from anywhere and renew every window. The counter now runs on the authenticated paths,
where the key is the caller's own id, and the unauthenticated sign-in path relies on the bounds it
actually has: five attempts per challenge and three codes an hour to a number.

#### 19.8 The `Authenticators` seam, and the hole it closes

`Authenticators` is a `Context.Reference` monoid modelled on `AuthHooks`: `list` concatenates
left-to-right, `revokeAll` sums, both sequentially because they run inside the caller's transaction
under its existing row lock — so an implementation may not do IO of its own. Absent members answer
`[]` and `0`, stated once in the module rather than at each call site, because a call site that got
the fallback wrong would fail *open* on exactly the two decisions below.

It closes a hole that predates this wave. `Accounts.unlink` refused to remove the last `accounts`
row; it could not see that a person's only remaining way in was a passkey, and it could not see that
a `local:credential` row carrying no hash is not a way in at all. Both are now counted, inside the
existing lock. And the email-otp takeover defence — §10's unproven-account rule, now running on
sign-in, address-verification *and* password-reset — sweeps contributed authenticators inside the
transaction, under the user-row lock, rather than after the commit: a sweep after the commit leaves
a window in which the pre-registrant's passkey still works.

`AuthenticatorSummary.restricted` is the SMS flag: a restricted factor may never be a person's only
second factor and never contributes a phishing-resistant level.

**The sum has to be complete on both sides.** `Passkeys.remove` had no symmetric check, so a
passwordless account whose only credential was one passkey could delete it and be locked out —
while `Accounts.unlink` was busy counting that same passkey as the reason an unlink was safe. It now
refuses `CannotRemoveLastAuthenticator` (409). The count is currently written twice, here and in
`Accounts.unlink`; it should be one exported helper, and the two spellings must not drift until it
is.

#### 19.9 Email-otp supersedes magic link

`src/magic-link/`, `MagicLinkClient` and `MagicLinkTest` are deleted. §10 is superseded: its
enumeration rules, its unproven-account rule and its five recorded deviations all carry forward,
with these changes.

**The hybrid.** A sign-in issuance mints the challenge *and* a plain `Verifications` link token at
the **same identifier**, so retiring by identifier retires both: consuming the code kills the link,
and following the link kills the code. Ordering is load-bearing — a link minted before `issueCode`
would be swept away by its own issuance. The link is the magic link reborn, at
`GET /auth/email-otp/link?token=`.

**There is no `signUp` purpose.** A caller-declared sign-in/sign-up split is only useful if the two
behave differently, and behaving differently for a known and an unknown address is precisely the
enumeration oracle §10.1 closes. Signing up is what a sign-in code *does* when the address turns out
to have no account and `disableSignUp` is off. `disableSignUp` surfaces at `verify` as
`SignUpDisabled`, never as `UserNotFound`.

**There is no `exchange`.** Magic link needed a non-redirect twin because a link was the only
credential. The code *is* that twin, and it is also the cross-device story: read it on the handset,
type it into the laptop.

**Enumeration safety is structural, not prose.** The address lookup, both row writes and the handle
cookie happen on *every* path; where a code could never do anything the rows are minted and then
discarded, so the write cost matches and a handle is still returned. Delivery is forked into the
layer's own scope, off the request's clock, because a mail awaited only on the known-address branch
is a timing oracle whatever else the endpoint equalises.

**A challenged sign-in is answered, not refused.** Magic link failed closed with
`PolicyRefused("mfa_required")` because a redirect has nowhere to prompt. Email-otp's JSON `verify`
answers 202 `MfaRequired`; its link redirects to `?mfa=required`. Both set the pending cookie and no
session cookie.

#### 19.10 A plugin owns its tables, and its own migration set

No plugin adds a column to a core table. Each ships `Migrations.make` numbered from `0001` in a
bookkeeping table of its own — `effect_auth_username_migrations`,
`effect_auth_anonymous_migrations`, `effect_auth_passkey_migrations`,
`effect_auth_two_factor_migrations`, `effect_auth_phone_migrations` — with varchar-bounded ids and
hashes so the `db-expansion.md` MySQL port stays mechanical, foreign keys `ON DELETE CASCADE`, and
both dialects through `sql.onDialectOrElse`. None is registered globally: the consumer composes it
and sequences it after this library's own, because every one of them references `users`.

Email-otp and One Tap own no table at all.

The SQLite branch of every migration added in this wave is unexercised — the suite is PGlite-only,
the same gap `0005_session_remember_me` already had.

**Anonymous is the exception on marking, and says why.** A visitor is a real `users` row at
`anon-<uuidv7>@anonymous.invalid` (RFC 2606 reserves `.invalid`), marked in a table of the plugin's
own and **never** by an `is_anonymous` core column: adoption is a `DELETE`, which no `UPDATE` on a
shared row can be rolled back around. Exclusion is `aal0` and one guard —
`requireAssurance({ aal: "aal1" })` — so no endpoint needs an `isAnonymous` check and none should
grow one.

#### 19.11 Passkeys, and the one optional dependency

`effect-auth/passkeys` is the only subpath a plugin gets, and it exists so that nothing reachable
from `effect-auth`, `effect-auth/client` or `effect-auth/testing` names `@simplewebauthn/server`.
That package is an **optional peer dependency** reached only through `WebAuthn.layerSimple`'s
dynamic `import`; a deployment that composed the plugin without installing it fails to *boot*
(`WebAuthnUnavailable`) rather than answering 500 at the first ceremony. Every other plugin in this
wave reaches consumers from the root barrel.

The `WebAuthn` seam is delegation with the policy kept back. What the dependency verifies is
signatures. What `Passkeys` owns is everything the verifier cannot know: the mandatory ceremony tag
(`registration` | `authentication`, which closes a real bug in the prior art), configured
`rpId`/`origin` **never** read from a request header, the bound-user check, the `userHandle` check
on discoverable sign-in, a credential-id unique index across the whole table, and the sign-count
policy.

Two sign-count decisions are worth the space. `layerSimple` passes `counter: 0` to the dependency
so that its own hard-fail policy is not applied — the policy is this library's: skip when both
counters are zero (a synced passkey never counts), otherwise publish
`PasskeyCounterRegression` and refuse only under `rejectCounterRegression`. And when a regression is
*tolerated*, the stored counter keeps the **high-water mark**. Writing the lower presented value
back erased the clone signal after a single event: with the row rewritten downwards the real
device's next ceremony and the clone's next one both look clean, so a deployment watching for
exactly that alternation would see one blip and then silence.

Evidence is read off the authenticator's real UV bit and never off the requested
`userVerification`, so a UV=1 ceremony reaches `aal2` in one step with no second prompt and a UV=0
tap is `aal1`. The per-user handle is 32 random bytes, never the user id: WebAuthn's `user.id` is
stored by the authenticator, synced, and shown to the person, and a database key is not opaque in
the privacy sense.

#### 19.12 Trusted devices and recovery codes, and where they sit

A recovery code is `possession`, recorded under its own name rather than dressed up as a TOTP code,
so `allowRecovery: false` can refuse it on the endpoints where a printed code is not good enough —
and the recovery path answers a real session, so that policy decides rather than a silent refusal
locking somebody out of the page where they would repair their second factor.

A **trusted-device skip is not a factor**: `factor: "none"`, so `deriveAal` gives it no weight. NIST
does not recognise device trust as a factor and RFC 8176 has no value for it.

Two limitations are recorded rather than hidden:

- **The skip is not on the session's log.** `SignInDecision`'s `Proceed` carries no evidence, and
  only `SignIn.complete` mints, so a decider has nowhere to put it. A session established through a
  remembered browser is therefore indistinguishable from one where no second factor was ever
  required. Consequently `Options.trustedDeviceSatisfies: "aal2"` **cannot be honoured**; it warns
  when the layer is built and behaves as `"none"`, which fails closed. One optional `evidence`
  member on `Proceed`, appended by `SignIn.complete` before `sessions.create`, closes both.
- **The revoke-on matrix is now wired, and was not.** `TwoFactor.layer` runs the subscription
  itself, forked into the plugin's own scope: password change (both `viaReset` values), address
  change, and sign-out-everywhere forget every remembered browser, as do enrolling, disabling,
  spending a recovery code and regenerating the set. Left as a five-line recipe in a README, the
  shipped default was that a browser phished into being trusted survived a password reset for thirty
  days — the exact permanent bypass the absolute expiry was written to bound. Deliberately **not**
  swept: `SessionRevoked` with scope `single` or `others`, and `PasswordResetRequested` (a request is
  not a change). A `PluginEvent` naming no user sweeps nobody.

A deployment running another factor plugin states the extra rule through `Options.alsoSweepOn`
rather than this plugin naming another's event strings: a plugin is seams, not a registry of the
others.

#### 19.13 One Tap reuses the verifier that exists

One Tap is not a verification path. It checks the browser bindings, then hands the credential to the
existing `oauth/IdToken.verifyIdToken` with the registered provider's own issuer, audience and key
source, then to that provider's own `userInfo` — which is where the `hd` hosted-domain rule lives —
then to the existing `Accounts.linkOAuth` and `SignIn.complete`. It reads no claim itself. A
grep-level test asserts that nothing under `src/one-tap/` imports a JWS library or fetches a key set
of its own.

It stores **no provider tokens**: a One Tap credential is not an OAuth grant, and writing an empty
token set would wipe what a real authorization-code flow stored for the same account.

The nonce is minted by this server into `__Host-effect_auth.onetap_nonce`, echoed through Google,
and compared *inside* `IdToken.verify` against what Google signed; the page's own copy, if it sends
one, must also agree with the cookie. Redirect mode additionally requires `g_csrf_token` to equal its
cookie.

#### 19.14 Toll fraud is a money question, so the defaults are closed

`Phone.allowedCountries` defaults to `[]`, and an empty list refuses **every** number before a
message, a row or a rate-limit token is spent. An SMS is the one thing this library does that costs
money per request.

Both capabilities that make a number a *factor* are off by default — `signIn` and `stepUp` — because
the PSTN is the channel NIST 800-63B §3.2.9 restricts. The shipped configuration keeps a number as a
contact detail: `summaryOf` reports `secondFactor: false` and nothing about an account's assurance
moves when one is attached. Turning `stepUp` on turns `requireAlternateSecondFactor` on with it
unless that is stated, so the rule that a restricted channel may not be somebody's only second
factor arrives at the moment the channel becomes one. A deployment that genuinely wants SMS to stand
alone says `false` and means it.

Four buckets guard a send: destination number, destination **prefix** (country code + 3 digits),
authenticated subject, and client address. The prefix bucket is the one that sees the actual attack —
premium-rate fraud pays for traffic to a *range*, not to one handset — which is why a step-up send
spends it too, and why a number the current allowlist no longer names is bucketed by its own calling
code rather than let through uncounted.

#### 19.15 Cross-cutting decisions this wave settled

**The origin guard.** Every unauthenticated POST that mints a session or sends a message calls
`OriginCheck.requireTrustedIfPresent`: present-and-untrusted is `OriginNotAllowed` (403 — 401 would
invite a caller that presented no credential to go and get one), absent passes, `Origin: null` is
refused, and `Referer` is the fallback.

The published guard reads `AuthConfig` from the *request* context, which would leave a plugin's
whole handler layer with a request-time requirement that `AuthTest.layerHttpApi`'s `extra` parameter
cannot discharge — which is why the first plugins written in this wave each composed the rule by
hand from `claimedOrigin` and `isTrustedOrigin`. They should not have.
`Effect.provideService(requireTrustedIfPresent, AuthConfig, config)` at layer build discharges the
configuration and leaves only the request, which a handler already has. That is the one way to
reach it; a hand-composed copy is a second spelling of "which origins are trusted", which is the
bug `OriginCheck` exists to prevent.

**It applies to core's own doors too, and that was not true when the wave started.** For most of
this wave every plugin's unauthenticated POST called the guard while core's `signUpEmail`,
`signInEmail`, `requestPasswordReset` and `sendVerificationEmail` did not — login-CSRF refused at a
plugin door and accepted at the library's own. The four now carry it and declare `OriginNotAllowed`,
which is wire-visible on each. There is no unauthenticated POST left in this library that mints a
session or sends a message without it, and a new one is not finished until it does.

**Service keys.** Amendment 17's scheme holds, including its elision rule: a key is
`effect-auth/<module path>/<Identifier>`, with `<Identifier>` dropped when it only repeats the file
name. Several keys added in this wave stuttered it. Four were collapsed —
`effect-auth/passkeys/WebAuthn`, `effect-auth/two-factor/TwoFactor`, `effect-auth/phone/Phone`,
`effect-auth/one-tap/OneTap` — and `WebAuthnClient`'s was corrected to name the module it actually
lives in (`effect-auth/client/internal/webauthn/WebAuthnClient`). Keys whose identifier genuinely
differs from the file name keep both segments: `phone/Phone/SmsSender`,
`two-factor/TwoFactor/TwoFactorEmails`, `passkeys/Store/PasskeyStore`.

**Two are still stuttering and should be collapsed together:**
`effect-auth/domain/SignIn/SignIn` and `effect-auth/domain/Challenges/Challenges`. `SignIn.ts`
restates its own literal in `signInOf`, which is Amendment 17's consequence 1 exactly — a typed view
reads the *same* context slot through a narrower shape, so the class declaration and the `…Of`
helper must be renamed in one edit or the helper silently becomes a second, unprovided service. That
is the failure mode Amendment 17 was written against, and it is why this is worth doing in one
commit rather than opportunistically.

These keys are process-local context slots and are never serialized, so nothing that moved here
moved a wire format.

**A plugin installs at two depths when its seams are references.** `SignInPipeline`, `Authenticators`
and `AuthHooks` are read when the services that consult them are built, so a contributor must be
provided **underneath** `Auth.layer` while the plugin's service goes over it. Two-factor
(`layerSeams` / `layer`) and anonymous (`layerHooks` / `layer`) both do this, and both take the same
options twice. It is the least surprising arrangement available and it is still surprising; a
deployment that installs only one half gets a coherent deployment with a seam missing and no
warning.

**Deferred, and named so it is not rediscovered.** Both hook points gained
`current: Option<SessionWithUser>` — the merge seam anonymous conversion needs — but no HTTP handler
populates it yet, so merge-on-sign-in is reachable only from a direct domain call. The *ordering*
hazard it used to carry is gone (19.2): the merge now hangs on `beforeSessionMint`, behind the
decision, so a challenged sign-in can no longer leave a visitor deleted with no session minted.

**The per-account two-factor lockout is not switchable by `rateLimit.enabled`.** `TwoFactor` spends
its lockout bucket through `RateLimits.consumeKeyed({ always: true })`: `rateLimit.enabled` is the
IP-throttling switch a deployment turns off because it has an edge limiter, which is an address
concern and not an account one, and a brute-force bound on a six-digit code must not ride it. Every
other keyed bucket this library ships is a throttle and still honours the flag.

#### 19.16 Breaking-change ledger

Every observable break this wave makes, in one list. `CHANGELOG.md` carries the same set with the
call-site detail; this is the reviewer's checklist.

**Wire and endpoints**

1. `Session` gains `authenticatedAt`, `aal` and `methods` in every variant including `json`, so
   `GET /auth/session` and `/auth/sessions` bodies change, and `methods` is carried as a JSON
   *string*. Every outstanding cookie-cache snapshot misses once — safe, the `rememberMe`
   precedent (§16.2).
2. `POST /auth/sign-in/email` answers a two-status union, 200 or 202.
3. `SessionNotFresh` is removed from the wire. `StepUpRequired` (403) replaces it and, being
   declared on `Authenticated`, appears on **every** authenticated endpoint. `InvalidCode` (401) is
   new.
4. `POST /auth/delete-user` is now guarded on every path, including `confirmByEmail` with no
   password, where a stale session could previously ask for the confirmation mail.
5. `POST /auth/reauthenticate` is new.
6. `signUpEmail`, `signInEmail`, `requestPasswordReset` and `sendVerificationEmail` declare
   `OriginNotAllowed` (403) and refuse a present-and-untrusted `Origin` or `Referer`.
7. Every magic-link endpoint is gone: `POST /auth/magic-link/sign-in`,
   `GET /auth/magic-link/verify`, `POST /auth/magic-link/exchange`.
8. New cookies: `__Host-effect_auth.pending`, `__Host-effect_auth.email_otp_handle`,
   `__Host-effect_auth.passkey`, `__Host-effect_auth.tdev`, `__Host-effect_auth.onetap_nonce`, and
   the three phone handle cookies.

**Services and types**

9. `SessionStoreService` gains `elevate`; `SessionsService` gains `elevate`, loses `requireFresh`,
   and renames `create` to `createUnchecked`. A replacement implementation must follow.
10. `PasswordsService.signIn`'s success is `SignIn.SignInResult`; `Passwords.SignInResult` is deleted.
11. `AuthHooks` gains `beforeSessionMint`, and both session hooks' context gains `current`.
    `AuthEvent` gains `SessionElevated`, and `SignedIn` gains `methods` — an exhaustive match must
    add both.
12. `AuthConfigService` gains `assurance.stepUpWindow`; a hand-built configuration must supply it,
    as it must `trustedOriginSet` (§14).
13. `OAuthProviderConfig.emailVerified` is **required** (`"derived" | "never"`), enforced by
    `makeRegistry`; every hand-written provider must state one. A `"never"` provider can never
    implicitly link onto a local account holding the same address.
14. `OAuthFlow.CallbackResult` gains `challenge`; when it is present `session` and `token` are null.
    `OAuthFlow.make`/`layer` no longer require `Sessions`.
15. `Accounts.unlink` counts authenticators as well as accounts, and no longer counts a
    `local:credential` row with no hash. A user with one provider row and a hashless credential row
    can no longer unlink themselves into a lockout.
16. `TokenService` gains `generateNumericCode`; `HmacService` gains `signedValue` /
    `verifySignedValue`. Breaking for implementors, not for consumers.
17. The client's atom wrappers moved from `client/internal/atoms.ts` to `client/Atoms.ts` and are
    public as `AuthAtoms`. `AuthClient.signIn`'s success is a union; every authenticated atom's
    error union gains `StepUpRequired`.
18. `AuthTest.Settings` gains `authenticators` and `signInPipeline`; `TestEmails` gains `smsKind`
    and `sms`.

**Database**

19. Core migration `0006_session_assurance`. Consumers merging `Migrations.migrations` number their
    own above `0006`, and any hand-written `INSERT INTO sessions` must state `authenticated_at`,
    which has no `DEFAULT`.
20. Five new plugin migration sets, each in its own bookkeeping table, none registered globally.

**Behaviour, at unchanged signatures**

21. A person with a confirmed second factor is challenged on **every** sign-in path.
22. `Phone` ships refusing every number (`allowedCountries: []`) and with both factor capabilities
    off; turning `stepUp` on turns `requireAlternateSecondFactor` on with it.
23. `Passkeys.remove` refuses `CannotRemoveLastAuthenticator` (409) rather than allowing a
    passwordless account to delete its only credential.
24. `TwoFactor.layer` now runs the trusted-device sweep subscription itself.
25. The two-factor factor-management endpoints ask for a named method rather than `aal2`, so a
    session that reached `aal2` without answering *this* plugin's factor no longer passes them.
26. `SessionCache` writes its envelope through `Hmac.signedValue` — byte-identical, no snapshot
    invalidated by the move itself.

### 20. Tagged unions on Effect primitives (2026-09-02)

The tree carried 192 hand-rolled `_tag` sites in `src/`: union types spelled member by member,
`{ _tag: "X", ... }` literals, `value._tag === "X"` checks, `Extract<E, { readonly _tag: … }>`
derivations, and five byte-identical copies of the `SqlError` unique-violation test. Meanwhile it
already declared 47 `Schema.TaggedError`s and 15 `Schema.TaggedStruct`s and never called the
constructors they provide, used `Result.isFailure` in `src/crypto` while inspecting `._tag` on the
same `Result` type everywhere else, and never touched `Data.taggedEnum`, `Match`, `Predicate.isTagged`
or `Schema.toTaggedUnion`. This amendment moves all of it onto the primitive rc.112 ships for each
case. `CHANGELOG.md` has the call sites; this records the decisions.

**The tag values are unchanged.** They are wire bytes (`{"_tag": "InvalidCredentials"}`), they
derive the OpenAPI component names, and the redirect error codes are computed from them. The
byte-compared OpenAPI snapshot did not move. What changed is how tagged values are declared,
constructed and inspected. Nineteen `_tag` spellings remain in `src/`, all of one of three kinds:
`{ readonly _tag: string }` as a generic constraint (core has no alias and writes it the same
way), the literal key in `Schema.toTaggedUnion("_tag")`, and doc lines explaining `"_tag" in result`
for the client unions whose other arm carries no tag.

#### 20.1 Which primitive, where

- **In-memory, never serialised** → `Data.taggedEnum`: `ProvisionSource`, `SignInDecision`,
  `VerifyResult`, `PasskeyAuthentication`, `Factor`, `ChallengeSubject`. Each exports a value of
  the same name beside the type with constructors, `$is` and `$match`. The values are plain objects
  with the same shape as before, so an existing literal still typechecks. `$is` checks only the
  tag; every site that uses it is on a value this process built, never one decoded from a request.
- **Crosses the wire** → `Schema.TaggedStruct` per member, `Schema.toTaggedUnion("_tag")` over the
  union: `AuthEvent`, `EmailOtpResult`. Encoding is identical to `Schema.Struct` with a
  `Schema.tag` field, which the snapshot proves. `.guards` are full structural checks.
  `MfaRequired` stays a `Schema.Struct` with a `Schema.tag`: piped through
  `HttpApiSchema.status(202)`, a `TaggedStruct` emits the same declaration but drops the field
  docs from the `.d.ts`, and `.make` fills `_tag` either way.
- **A success or a failure** → `Result`. `CallbackOutcome` and `LinkOutcome` were both
  `{ _tag: "Success" } & S | { _tag: "Failure"; error; redirectTo; code }`, which is
  `Result.Result<S, RedirectFailure<E>>` with the failure fields hoisted. `RedirectFailure<E>` loses
  its `_tag` and `redirectFailure` returns the `Result` directly. This supersedes the value shape
  Amendment 16.4 describes; the construction still lives once, as 16.4 requires.
- **A closed code table** → `Match.tagsExhaustive`. The two `errorCode` maps were total mapped
  types over `E["_tag"]` whose whole point is that a new union member is a compile error rather
  than an `undefined` code in a redirect. `tagsExhaustive` gives the same compile error and absorbs
  the `OAuthProviderError` case that used to sit outside the map as a ternary.
- **A tag check in an Effect pipeline** → `Effect.catchTag` (the rc.112 array form),
  `Effect.catchReason` for a nested `reason._tag` (`RateLimiterError`), `Filter.reason` for a retry
  predicate over one (`HttpClientError`). Where a site used `Effect.result` only to re-fail one tag
  and handle the rest, the `Effect.result` is gone: `catchTag` names the tags it handles and leaves
  `PersistenceError` in the channel with its original `Cause`. Where a `Result` genuinely has to
  exist (a field of the failure is read after unwrapping), `Result.isSuccess` / `isFailure` /
  `match` / `getOrElse` / `merge` replace the `._tag` comparison.
- **A derived type** → `Types.ExtractTag`, `Types.ExcludeTag`, `Types.Tags`.
- **The five `kindOf` copies** → `Stores.persistenceFailureKind`, one classifier in `domain/Stores.ts`
  beside `isUniqueViolation`. It imports `SqlError` from `effect/unstable/sql` into `domain/`;
  `PersistenceError` already lives there and this only classifies the driver failure that produces
  it, so the layering rule (domain never imports http) is intact.

#### 20.2 Where rc.112's types forced a fallback

Three places could not take the primitive the plan named. Each was tried, refused by the
compiler, and replaced with the nearest primitive; none needed a cast, and the cast budget is
still five.

1. **`SignInResult<F>` is not a `Data.taggedEnum`.** It is generic in `F extends UserFields`.
   `Data.TaggedEnum.WithGenerics<1>` declares its parameter as `unknown` and `TaggedEnum.Kind`
   applies no constraint, so `UserOf<this["A"]>` fails with `TS2344`. `SignInComplete<F>` is a
   declared interface, `SignInChallenge` is `Data.TaggedEnum.Value<SignInDecision, "Challenge">`
   so the challenge shape is written once, and the `SignInResult` value is a hand-written bundle
   (`Complete`, `Challenge` aliased to `SignInDecision.Challenge`, `$is` which is
   `Predicate.isTagged`, `$match` over `SignInDecision.$is`). It is the one place in `src/` that
   still writes `_tag: "Complete"`, and it is the union's single declaration.
2. **`dieOn`, `serverFault` and `withStepUp` keep `Effect.catchIf`.** `Effect.catchTag`'s tag
   parameter is constrained by `Types.Tags<E>`, a conditional TypeScript leaves deferred while `E`
   is a type parameter, so no literal satisfies it inside a function generic in `E` (`TS2769`).
   `Filter.tagged` has the same constraint. The refinement's test is now `Predicate.isTagged` and
   its type is `Types.ExtractTag<E, …>`; the comment explaining why the pass-through must re-fail
   the original `Cause` stays.
3. **`redirectFailure`'s policy-refusal narrowing is a local refinement, not bare
   `Predicate.isTagged`.** `isTagged` refines to `{ _tag: K }` without intersecting the input, so
   `error.code` would not typecheck. `(error: E): error is E & PolicyRefused =>
   Predicate.isTagged(error, "PolicyRefused")` carries the hook's `code` through with no cast.

Two related refusals worth recording: `AuthTest.tagsOf` cannot answer `ReadonlyArray<Types.Tags<E>>`
for the same deferred-conditional reason and still answers `ReadonlyArray<string>`; and
`Stores.isUniqueViolationFailure` is a retry `while:` only — on a channel that is already
`PersistenceError`, using it as a `catchIf` refinement would compute `Exclude<PersistenceError,
PersistenceError> = never` and erase an error the runtime can still raise.

#### 20.3 Behaviour that moved, deliberately

- A `PersistenceError` inside `OAuthFlow.complete`, `EmailOtp.follow`, `Passwords.signUp` and the
  passkeys session lookup now propagates with the `Cause` it was raised with; before, it was
  unwrapped from a `Result` and re-failed, which dropped annotations.
- The session middleware's verify path no longer rewrites an `Unauthorized` from
  `Sessions.verify` into a fresh `Unauthorized`; only `SessionExpired` is rewritten. Same tag,
  same empty payload, same 401.
- The anonymous merge hook's `catchIf(not PolicyRefused, die)` became
  `catchTag(["PersistenceError", "SqlError"], die)`: the statement inverted from "everything that
  is not a refusal" to the two failures the hook can raise, so a failure added later must be
  classified there rather than silently becoming a defect.
- `test/domain/Events.test.ts`'s coverage assertion compares sorted tag sets from
  `AuthEvent.discriminants` rather than counts, so a member added without a sample is named.
- Every wire-schema constructor (`X.make`) validates its fields at construction and throws on a
  failing check; the literals it replaced ran nothing. Every input is a typed value this library
  built, so no site can fail in practice; it is recorded because it is a new defect path and a
  validation per published event.

Test assertions of the form `assert.strictEqual(x._tag, "…")` were left as they are: they assert a
wire value, which this amendment fixes as unchanged, and a guard would assert less.

### 21. Databases: PostgreSQL, SQLite and MySQL (2026-09-02)

`db-expansion.md` is the design and `db-expansion-plan.md` is the execution contract; this amendment
records what the wave decided and what building it learned. The claim it establishes is narrow and
testable: **the whole suite, every file, runs on PostgreSQL, SQLite and MySQL**, and a deployment on
any of the three gets the same guarantees — exactly-once consumption of a verification, a reclaim
lock that one writer wins, uniqueness that means byte equality, and a rollback that exposes no
partial state.

Two boundaries made this a portability project rather than a persistence redesign, and they hold:
the domain depends on the `Stores` interfaces, and the stores depend on `SqlClient.SqlClient` rather
than on a driver. Nothing in `src/domain/`, `src/http/` or `src/oauth/` learned a dialect.

#### 21.1 Three dialects, and a refusal

Supported: PostgreSQL, SQLite (`node:sqlite`, so Node 22 is the floor) and MySQL 8.0.19 or later.
PGlite is PostgreSQL and is not a fourth dialect — it reports `"pg"`, which is what it is. MariaDB
is not supported, because the conditional upsert uses MySQL's `INSERT … AS new ON DUPLICATE KEY
UPDATE` row alias. MS SQL and non-relational stores stay out of scope; an application that needs one
provides the five store interfaces itself, which is what that seam is for.

Effect SQL's `Statement.Dialect` has five members. `Dialect.dialectOf(sql)` is the single place the
ambient client's dialect is read, and it *dies* — naming the dialect the driver reported — on the
two this library does not support. A silent inheritance of PostgreSQL behaviour is the failure mode
that decision refuses.

#### 21.2 One kernel for what the dialects disagree about

`src/sql/Dialect.ts` holds the four things they genuinely disagree about, and each exists once:
`booleanCodec` (encode per dialect; one total decode; `decodeNullable` preserving null and
undefined), `lockClause` (` FOR UPDATE` on pg and mysql, empty on sqlite), `columnType` over a
`ColumnRole` union, and `booleanLiteral`. `identifier(sql, name)` is the escaped-identifier fragment
that replaces every `sql.literal(<name>)` and every `sql.unsafe` that interpolated one.

That is the "one way to do each thing" rule applied to a place that had three: three copies of the
lock clause and two of the boolean codec. `SqlStores.decodeSqliteBoolean` is deleted with them,
which is the wave's only removal from the server package's public surface.

**A behaviour change on impossible input, recorded because it is one.** The boolean decode is now
total (`value === true || value === 1`) where PostgreSQL's was an identity pass-through. For every
value PostgreSQL can produce the answer is identical; for a value it cannot, the old code failed
schema decoding loudly and the new code answers `false`. One total reader was judged worth more than
a per-dialect branch.

#### 21.3 MySQL has no `RETURNING`, and what follows from it

`src/sql/Mutations.ts` holds six helpers — `insertAndRead`, `updateAndRead`, `deleteAndCount`,
`deleteAndRead`, `consumeOne`, `upsertAndRead`. On PostgreSQL and SQLite each renders the single
statement the store wrote before. On MySQL each is a `sql.withTransaction` block when it is the
outermost one, and the caller's own transaction — opening nothing, not even a savepoint — when the
caller is already inside `WithAuthTransaction`: a MySQL deadlock rolls the whole transaction back,
so a savepoint taken inside it stops existing at that moment and the `ROLLBACK TO SAVEPOINT` that
would follow is a defect over a statement with a perfectly good typed failure of its own. On
PostgreSQL and SQLite a nested block is the savepoint `sql.withTransaction` gives it.

The MySQL shape is **lock the row, then mutate, then read back by its key**, and not the "update
then select" the design doc sketched. Three reasons, all load-bearing:

- `ROW_COUNT()` after an `UPDATE` counts rows *changed*, not *matched*. `SessionStore.touch` under a
  frozen clock writes the same expiry and the same `updated_at`, so a count-based answer would be
  `None` on MySQL where PostgreSQL answers `Some`.
- Selecting by the key *after* a guarded update returns a row the guard refused — `confirmTotp`'s
  `WHERE verified_at IS NULL` is the case. The read has to be of the row the predicate actually
  matched, which is the row the `SELECT … FOR UPDATE` took.
- **Every read-back is a locking read.** `REPEATABLE READ` fixes a transaction's snapshot at its
  first consistent read, and neither an `UPDATE` that assigns the values a row already holds nor an
  `ON DUPLICATE KEY UPDATE` whose `IF` resolves to the stored value writes a new row version — so a
  plain read-back answers `None` over a row a neighbour committed after that snapshot, which is a
  caller's own username reported as somebody else's. `insertAndRead` is the exception, because a
  transaction always sees its own insert.

`consumeOne` — the exactly-once claim — is `SELECT … FOR UPDATE` with `LIMIT 1`, then a delete by
the selected primary key. That diverges from `DELETE … RETURNING` on the other two dialects if a
predicate ever matched two rows: MySQL would claim one, they would claim both. Every predicate it is
used with carries a high-entropy digest, so a second match is a hash collision, and the divergence is
documented at the helper rather than hidden.

`upsertAndRead` expresses the two conditional upserts this library has — the username claim and the
TOTP enrolment (`WHERE verified_at IS NULL`). It carries two hazards MySQL's syntax cannot type
away, and both are constraints on the call sites: `ON DUPLICATE KEY UPDATE` fires on *any* unique key
the insert collides with and cannot be told to care about one, and its assignments are evaluated left
to right with each seeing what the previous wrote — so a column the condition reads must be assigned
**last**.

#### 21.4 Column roles: what a bound is, and what a collation is for

PostgreSQL and SQLite use unbounded `text` throughout, as before. MySQL cannot: an indexed column has
to be bounded and a unique index has to stay under InnoDB's 3072 bytes. So every column has a *role*
— `id`, `hash`, `credential`, `email`, `identity`, `identifier`, `timestamp`, `boolean`, `number`,
`bigint`, `text` — and `columnType` is the only place a role becomes a type. The lengths and the
constraints that guarantee them are the table in README "Databases"; the rules behind it are:

- An indexed MySQL column is never `text`.
- Every bound is guaranteed by something the domain already enforces — a UUIDv7 is 36 characters, a
  base64url SHA-256 is 43, RFC 5321 caps an address at 320, E.164 at 16, a WebAuthn credential id at
  1023 *raw* bytes, which is 1364 characters in the base64url spelling actually stored (the
  `credential` role is `varchar(1368)`, and `Passkey.credentialId` states the same bound in the
  domain) — and both halves of the widest unique index (`issuer` + `account_id`) fit InnoDB's limit
  with room.
- **Opaque identity never inherits the server collation.** `ascii_bin` and `utf8mb4_0900_bin` compare
  byte by byte. Under MySQL's default `utf8mb4_0900_ai_ci`, `Ada` and `ada` are one row and so are
  `a` and `á` — which would make a token digest, an OAuth subject or a username key collide across
  values this library treats as distinct, and would make one person's credential answer for
  another's. E-mail is lower-cased by the domain before storage, so `utf8mb4_0900_bin` is exactly the
  rule the other two dialects apply.
- **`utf8mb4_0900_bin`, not `utf8mb4_bin`, because the latter is PAD SPACE.** MySQL ignores trailing
  spaces in every comparison made in a PAD SPACE collation, so `"sub"` and `"sub "` are one value and
  one row in a unique index, while PostgreSQL and SQLite see two. That reaches `accounts.account_id`
  — an identity provider's `sub` verbatim — and every custom string user field. `utf8mb4_0900_bin` is
  NO PAD and has existed since MySQL 8.0.17, inside the 8.0.19 floor. `ascii_bin` is PAD SPACE too and
  has no NO PAD sibling, but its roles are alphabets this library generates and none contains a space.
- **The unbounded `text` role states its character set too** (`text CHARACTER SET utf8mb4 COLLATE
  utf8mb4_0900_bin`). A bare `text` inherits the *database's* default character set, and a database
  created `CHARACTER SET latin1` refuses a name with an emoji with error 1366. The schema this
  library creates does not depend on how the database was created.

Custom string user fields are `varchar(255)` on MySQL. Per-field storage metadata is roadmap work,
not this wave.

**PostgreSQL and SQLite plugin DDL did move, and this is the record of it.** The four core tables
were already `text` throughout and did not change. The five plugin tables were not: they had been
written with bounded `varchar` on PostgreSQL "so the MySQL port stays mechanical", and the roles
replaced that with the same unbounded `text` the core tables use. So on PostgreSQL
`effect_auth_usernames.username_key`/`username` (`varchar(64)`),
`effect_auth_phone_numbers.phone_e164` (`varchar(16)`), every plugin `user_id`/`id` (`varchar(36)`)
and `effect_auth_passkeys.name` (`varchar(64)`) are now `text`, and every inline `REFERENCES`
became a table-level `FOREIGN KEY` (§21.5's MySQL reason; PostgreSQL and SQLite read the two forms
identically). Two consequences, both accepted: an existing PostgreSQL deployment keeps the columns
it has, because every plugin migration is `CREATE TABLE IF NOT EXISTS` and none of them alters a
column — a new deployment and an old one differ in column *type*, never in behaviour; and the
database-level length guard on `username_key` and `phone_e164` is gone on PostgreSQL, leaving the
domain guards that were always the real ones (`maxLength` 30 on a username, `E164.normalize` on a
number) and MySQL's `varchar` bound. On SQLite the natural keys moved from `PRIMARY KEY` to
`NOT NULL UNIQUE`, which is §21.5's rule and is a change to that dialect's DDL as well.

#### 21.5 The migrator on MySQL, and why migrations are a deploy step

Effect SQL's migrator runs the whole set inside `sql.withTransaction` and takes
`LOCK TABLE … IN ACCESS EXCLUSIVE MODE` on PostgreSQL only. Neither carries to MySQL:

- **DDL commits implicitly.** A migration that fails halfway leaves the tables it had already created
  *and* leaves itself recorded as applied, because the bookkeeping rows are inserted before the
  statements run. Recovery is by hand.
- **There is no cross-process lock.** The second process is turned away by the primary key on the
  bookkeeping table rather than made to wait, and returns immediately — possibly to serve against a
  schema the first has not finished building.

Both are documented in README "Databases", and both are reasons for the rule that was already right
everywhere: run migrations as a deploy step, not on boot. `Migrations.layer` remains a quickstart
convenience and is described as one.

MySQL has no `ADD COLUMN IF NOT EXISTS`. A migration runs once, so the mysql branches use a plain
`ADD COLUMN`; `Migrations.forUserFields(model)`, which is idempotent by design and may run on every
boot, asks `information_schema.columns WHERE table_schema = DATABASE()` first.

**SQLite classifies a lost race by which constraint lost it.** A conflict on a *declared* `PRIMARY
KEY` is reported as `SQLITE_CONSTRAINT_PRIMARYKEY` (1555) and only a conflict on a unique index as
`SQLITE_CONSTRAINT_UNIQUE` (2067) — and only the second is classified as a `UniqueViolation`, which
is what every caller that resolves a race branches on. So a **natural key whose lost race a caller
must classify is `NOT NULL UNIQUE` on SQLite, never a declared `PRIMARY KEY`**; the same constraint,
a different reported error. `effect_auth_phone_numbers.phone_e164` is the first table this was
applied to, and the rule is stated here so the next table does not inherit the bug by accident.

#### 21.6 The testing module carries the database

`effect-auth/testing` gains a `Database` seam. A `Database.Provider` is a layer that hands each
build a private, empty database and takes it away when the build's scope closes; `Database.fromConfig`
resolves one from `EFFECT_AUTH_TEST_DATABASE`, so the backend is a variable rather than a code change,
and `AuthTest.Settings.database` overrides it for a suite that must run on one backend whatever the
variable says. `effect-auth/testing/{sqlite,postgres,mysql}` are subpaths behind optional peer
dependencies, reached only by a dynamic `import()` — the same arrangement `effect-auth/passkeys` has
for `@simplewebauthn/server`. That is the invariant: `effect-auth/testing` reaches an optional peer
through `Database.fromConfig`'s `import()`s and never statically. It is not a claim about the tree's
`import()` count, which is five.

`Database.TestDatabase` is what a test may ask the database beyond SQL: `dialect`, `reset`, and
`tableNames` / `columnNames` / `indexNames`. Keeping `information_schema`, `pg_catalog` and `PRAGMA`
behind it is what lets one assertion be true on four backends; a test that reads a catalog directly
is a test that only runs on one. `reset` preserves every table whose name ends in `_migrations`, so
a migration test cannot be falsified by it.

**Breaking, and recorded in `CHANGELOG.md`:** `PgliteClient.PgliteClient` is gone from every exported
testing layer type, replaced by `Database.TestDatabase`. That leak made the harness's *type* name a
driver the library does not depend on; a consumer on another backend could not have named it.

#### 21.7 One suite, every dialect

There is no separate contract-test runner. The store, migration, error, concurrency and dialect-fact
contracts are ordinary files that read the dialect from `TestDatabase` and are therefore run four
times by CI (`check`, plus one full suite per dialect, all parallel, no shards). A test that needs a
dialect's own fact branches on `Database.dialect` inside itself, and there are few of them.

Speed is a standing consideration and the rules are part of the definition of done: module isolation
is off; one engine per worker and one schema or database per build; a test that needs an empty table
calls `reset` rather than opening another top-level `layer()` block. `isolate: false` is what makes
the per-worker memos in `src/testing` per worker rather than per file — the PGlite suite went from
32 s to 20 s at four workers — and a change that needs isolation back has to say what state it leaks.

**One plan decision changed shape in the build.** Per-worker PGlite with a schema per build could not
be made correct: `sequence.concurrent` overlaps two top-level `layer()` blocks in a file, PGlite has
one connection, and a second build's `search_path` moves under the first block's running tests. The
wave first shipped one instance per build, and the first CI run showed why that is not good enough:
a PGlite boot that costs a second on a laptop costs several on a shared runner core, two blocks hit
the 15-second hook timeout, and the PGlite job was the slowest of the five at 146 s. So PGlite is a
**pool of engines per worker**: a build borrows a whole engine — the previous block's, wiped with
`DROP SCHEMA public CASCADE`, or a freshly booted one when every engine is busy — and returns it when
its scope closes. The pool grows to the number of blocks that overlap in one worker, a handful, so a
suite of a hundred-odd blocks boots a handful of engines instead of a hundred-odd. `pg` and `mysql`
keep one server per worker and a database per build, which concurrent connections make safe.

#### 21.8 InnoDB takes a lock on the rows a predicate did *not* match

The one MySQL fact that changed a store's statements rather than its spelling. Under InnoDB's
default `REPEATABLE READ`, a `DELETE … WHERE <column> = ?` takes a next-key lock over the *gap* it
scanned — and when the predicate matches nothing, that gap is a single one every other writer with
a new key also wants to insert into. Three plugin operations begin by clearing what the caller
holds, so on a table that has never held a row every one of them matched nothing:
`UsernameStore.claim`, `PhoneStore.claim` and `TwoFactorStore.replaceRecoveryCodes`. Twelve people
signing up at once on a fresh MySQL deadlocked several of them — `ER_LOCK_DEADLOCK`, surfaced as a
`PersistenceError` of kind `Unknown`, a 500 on a sign-up burst.

**The answer is the statement shape, not a retry.** It is the one `Mutations.consumeOne` already
uses for the exactly-once claim (§21.3): read *plainly* which row to remove — a consistent read
takes no lock at all — and then delete by the primary key it found, or issue no delete when there
is none. `UsernameStore.claim` and `PhoneStore.claim` release through `consumeOne`;
`replaceRecoveryCodes` reads its set's ids and deletes them by key, because it clears many rows
rather than one. The three copies of a MySQL `DeadlockError` classifier and their three different
retry budgets are deleted with the hazard, and PostgreSQL never had one here.

One retry survives the wave, in the kernel rather than in a plugin: `Mutations.retryDeadlocks`, which
`VerificationStore`'s two range deletes use. A range delete over an identifier cannot be shaped out
of a gap the way a single-row claim can, it is idempotent, and the retry fires only on MySQL and only
when it is the outermost statement — inside a transaction InnoDB has already rolled back there is
nothing to retry, so the failure is reported (§21.9).

The price is stated where `consumeOne` states it: what a transaction clears is what was committed
when it read, so two replacements racing for one person can each leave their own set of recovery
codes — which is exactly what PostgreSQL has always done, its `DELETE` seeing the snapshot its
statement began with. Every code is that person's own and single-use. `test/username/Store.test.ts`,
`test/phone/Store.test.ts` and `test/two-factor/Store.test.ts` each carry a twelve-way first-claim
storm; each of them fails on the old statement shape on MySQL and passes on all four backends now.

#### 21.9 A MySQL deadlock ends the transaction, so the outermost one proves it survived

InnoDB answers a deadlock by rolling the *whole* transaction back — not the statement, and not to a
savepoint. A lock-wait timeout does the same where `innodb_rollback_on_timeout` is set, and any DDL
statement commits implicitly. Afterwards the connection is in autocommit and nothing in this process
was told.

Two consequences, and this wave answers both.

**Nested transactions on MySQL open nothing.** A savepoint taken inside a MySQL transaction is
exactly what a deadlock destroys, so Effect's `ROLLBACK TO SAVEPOINT` then fails with "SAVEPOINT …
does not exist" — a defect where the stores promise a `PersistenceError`. `Mutations.atomically` is
therefore the one way a store helper opens a transaction: on MySQL it opens nothing when a
transaction is already in flight, and `WithAuthTransaction.run` does the same for a nested run. On
PostgreSQL a failed statement poisons a transaction rather than ending it and `COMMIT` on a poisoned
transaction rolls back and says so; SQLite serialises writers instead of deadlocking them. Both keep
Effect's savepoint, and decision 10 holds for them.

**The outermost transaction asks the database whether there is still a transaction to commit.** A
body that *recovers* the failure — a hook that logs and continues, a store call wrapped in
`Effect.result` — would otherwise write in autocommit and then `COMMIT` successfully over half of
itself, which is the worst answer this seam can give. So on MySQL the outermost
`WithAuthTransaction.run` issues `SAVEPOINT effect_auth_transaction` after `BEGIN` and `RELEASE
SAVEPOINT effect_auth_transaction` before `COMMIT`: a savepoint does not survive an implicit
rollback, so a failing `RELEASE` is proof the transaction is gone and the run fails with a
`PersistenceError` instead. One fixed name is safe because only the outermost run takes one. Cost:
two statements per domain transaction, on MySQL only. `test/sql/Dialect.test.ts` pins it with two
fibers cross-locking two users.

**A deadlock is retried only where a retry can mean anything** — outermost, and on an idempotent
statement. That is `Mutations.retryDeadlocks`, and `VerificationStore`'s two range deletes are its
only callers (§21.8 for why nothing else needs one).
