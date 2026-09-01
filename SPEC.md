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
