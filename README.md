# effect-auth

Authentication for Effect applications: sessions, e-mail/password and OAuth, built on
[Effect](https://effect.website) v4 primitives — `Context.Service`, `Layer`, `Schema`, `HttpApi`.

```ts
const AuthLive = Auth.layerWithOAuth({
  baseUrl: "https://app.example.com",
  secret: Redacted.make(process.env.AUTH_SECRET!),
  emailPassword: { enabled: true },
  providers: [Github.make({ clientId, clientSecret: Redacted.make(clientSecret) })]
}).pipe(Layer.provide(PgLive), Layer.provide(MyMailer), Layer.provide(FetchHttpClient.layer))
```

That is the whole installation. Eighteen endpoints, an OpenAPI document, a typed client and a
`CurrentUser` in your own handlers' context.

## Why

Effect applications already have a service graph, typed errors, `Redacted`, `Schema` and a `Layer`
for every seam. An authentication library that lives outside all of that has to be integrated with
glue code, and glue code is where authentication bugs live. `effect-auth` is written *as* an Effect
service graph:

- **Every failure is a `Schema.TaggedError`** with an HTTP status annotation, so `InvalidCredentials`
  is a member of the endpoint's error union, is a `401` on the wire, and is a discriminated tag in
  the client — the same value at all three points.
- **Every secret is `Redacted<string>` end to end.** Passwords, session tokens, reset links and the
  signing secret are unwrapped at exactly one call site each, and there are tests asserting that a
  log line renders `<redacted>`.
- **Persistence is a four-service seam** (`UserStore`, `SessionStore`, `AccountStore`,
  `VerificationStore`). The SQL implementation is one layer over `SqlClient`; swapping it out is a
  `Layer`, not a fork.
- **Time is the `Clock`.** Session expiry, the rolling refresh, token TTLs and freshness all read the
  Effect clock, so `TestClock` moves them and a fourteen-day session lifecycle is a test that runs
  in milliseconds.
- **No hidden state.** No globals, no module-level singletons, no implicit request context: what a
  handler can reach is what its `Layer` provided.

### Attribution

The flows, the linking rules and the threat model are a debt to
[better-auth](https://better-auth.com) (MIT), whose semantics this library studies closely: account
linking gates, the single-use verification table, rolling session refresh, redirect refusal on
provider fetches. No code was copied — this is a ground-up rewrite on Effect v4 primitives — but the
design decisions worth stealing were stolen deliberately, and better-auth deserves the credit for
having got them right first.

**Scope: authentication only.** Sessions, credentials, OAuth. No roles, permissions or policies —
but `CurrentUser` and `CurrentSession` are clean context keys, so a policy middleware can `require`
them without this library growing an authorization concept.

## Install

```sh
pnpm add effect-auth effect@4.0.0-rc.112
```

`jose` is the only runtime dependency, and only OIDC `id_token` verification reaches it.
`@effect/sql-pglite` is an optional peer dependency, needed only by `effect-auth/testing`.

## Quickstart

```ts
import { Layer, Redacted } from "effect"
import { HttpApi, HttpApiBuilder } from "effect/unstable/httpapi"
import { Auth, AuthApi, AuthHandlers, Migrations } from "effect-auth"

// 1. Compose the auth endpoints into your own API.
const MyApi = HttpApi.make("app").addHttpApi(AuthApi).add(MyOwnGroup)

// 2. Configure the library. `Migrations.layer` runs the migrator on start-up,
//    which is a quickstart convenience — see "Migrations" below.
const AuthLive = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make(process.env.AUTH_SECRET!),
  emailPassword: { enabled: true, requireEmailVerification: true },
  trustedOrigins: ["https://admin.example.com"]
}).pipe(
  Layer.provide(Migrations.layer.pipe(Layer.provideMerge(PgLive))),
  Layer.provide(MyMailer)
)

// 3. Serve. `AuthHandlers.layer` implements the "auth" group of *your* API.
const ServerLive = HttpApiBuilder.layer(MyApi).pipe(
  Layer.provide(AuthHandlers.layer(MyApi)),
  Layer.provide(MyOwnHandlers),
  Layer.provide(AuthLive)
)
```

`Auth.layer`'s remaining requirements are exactly the two seams you own — a `SqlClient` and an
`AuthEmails`.

### OAuth is the other entry point

There is no `providers` option. A deployment that serves social sign-in calls `Auth.layerWithOAuth`
with a non-empty list of provider **values**, and gets back the same layer plus `OAuthFlow`, minus
nothing — the only new requirement is an `HttpClient`:

```ts
import { FetchHttpClient } from "effect/unstable/http"
import { Auth, Github, Google } from "effect-auth"

const AuthLive = Auth.layerWithOAuth({
  baseUrl: "https://app.example.com",
  secret: Redacted.make(process.env.AUTH_SECRET!),
  emailPassword: { enabled: true, requireEmailVerification: true },
  providers: [
    Github.make({ clientId, clientSecret: Redacted.make(githubSecret) }),
    Google.make({ clientId: googleId, clientSecret: Redacted.make(googleSecret) })
  ]
}).pipe(
  Layer.provide(Migrations.layer.pipe(Layer.provideMerge(PgLive))),
  Layer.provide(MyMailer),
  Layer.provide(FetchHttpClient.layer)
)
```

Which of the two you call is the whole decision: `Auth.layer` cannot provide an `OAuthFlow` and
cannot ask you for a transport, and `Auth.layerWithOAuth` cannot be called with an empty list.

### Reading the settings from `Config`

`Auth.layerConfig` and `Auth.layerConfigWithOAuth` are the same two layers with the scalar settings —
and, for the OAuth one, the provider credentials — read from `Config`:

```ts
const AuthLive = Auth.layerConfig({
  baseUrl: Config.string("BASE_URL"),
  secret: Config.redacted("AUTH_SECRET"),
  emailPassword: { enabled: true }
})

const AuthWithGithubLive = Auth.layerConfigWithOAuth({
  baseUrl: Config.string("BASE_URL"),
  secret: Config.redacted("AUTH_SECRET"),
  emailPassword: { enabled: true },
  providers: [
    Github.makeConfig({
      clientId: Config.string("GITHUB_CLIENT_ID"),
      clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
    })
  ]
})
```

A missing credential is one `ConfigError` when the layer is built, not a provider that answers
`UnknownProvider` in production.

### The mailer

```ts
const MyMailer = Layer.succeed(AuthEmails.AuthEmails)({
  sendVerification: (email) => send(email.user.email, "Confirm your address", Redacted.value(email.url)),
  sendPasswordReset: (email) => send(email.user.email, "Reset your password", Redacted.value(email.url))
})
```

Both methods may fail with `EmailDeliveryError`. The endpoints that trigger them still answer `200`
regardless — whether an address has an account must not be observable — so a delivery failure is a
signal for your logs, not for the caller.

### Your own protected endpoints

```ts
class TodosGroup extends HttpApiGroup.make("todos")
  .add(HttpApiEndpoint.get("list", "/todos", { success: Schema.Array(Todo) })
    .middleware(Authenticated)) {}

// …and in the handler:
Effect.gen(function*() {
  const user = yield* CurrentUser   // already verified; `401` never reaches here
  return yield* todosFor(user.id)
})
```

### Migrations

`Migrations.layer` runs the migrator when the layer is built. That is right for a local example and
wrong for a fleet, where a process restart must never be a schema change. In production either merge
`Migrations.migrations` into your own `Migrator` record (number yours above `0004`) or run them as a
deploy step, and provide `Auth.layer` with a bare `SqlClient`.

Every timestamp column is `text` holding an ISO-8601 UTC string. That is portable across Postgres
and SQLite and lexicographically sortable, which is what makes the expiry predicates correct on both.
SQLite deployments must enable `PRAGMA foreign_keys = ON` for the cascade deletes.

## Endpoints

All under `/auth`. Ten of them carry the `Authenticated` middleware and answer `401` without a
session.

| Endpoint | Method / path |
|---|---|
| `signUpEmail` | `POST /sign-up/email` |
| `signInEmail` | `POST /sign-in/email` |
| `signOut` | `POST /sign-out` |
| `getSession` | `GET /session` |
| `listSessions` | `GET /sessions` |
| `revokeSession` | `POST /revoke-session` |
| `revokeSessions` | `POST /revoke-sessions` |
| `revokeOtherSessions` | `POST /revoke-other-sessions` |
| `requestPasswordReset` | `POST /request-password-reset` |
| `resetPassword` | `POST /reset-password` |
| `changePassword` | `POST /change-password` |
| `sendVerificationEmail` | `POST /send-verification-email` |
| `verifyEmail` | `GET /verify-email?token=` |
| `signInSocial` | `POST /sign-in/social` |
| `oauthCallback` | `GET /callback/:providerId` |
| `listAccounts` | `GET /accounts` |
| `linkSocial` | `POST /link-social` |
| `unlinkAccount` | `POST /unlink-account` |

With `emailPassword.enabled: false` the seven credential endpoints answer `404`: they are declared
in the contract but not served by that deployment.

## Client

`effect-auth/client` is browser-safe — nothing reachable from it imports a node builtin, a database
driver or a password hasher. It wraps `AtomHttpApi`, so the session is an atom and the mutations
invalidate it.

```ts
import { Redacted } from "effect"
import { AtomRegistry, AuthClient } from "effect-auth/client"

const auth = AuthClient.make({ baseUrl: "https://app.example.com" })
const registry = AtomRegistry.make()

registry.mount(auth.session)
registry.set(auth.signIn, {
  email: "ada@example.com",
  password: Redacted.make(password)
})
```

`signIn`, `signUp`, `signOut` and the revoke mutations carry the reactivity key `"auth.session"`, so
the `session` atom refetches itself when one of them succeeds. `signInSocialUrl(payload)` returns
the provider URL to navigate to.

Read results with `AsyncResult.matchWithError`, not `AsyncResult.match`: `AtomHttpApi` makes
transport and decode failures *defects* and keeps only the endpoint's declared errors in the error
channel, so a UI wants `onError` and `onDefect` separated.

Passwords cross the boundary as `Redacted<string>` — `Redacted.make(plaintext)` at the input, and
the schema encodes it for the request body.

Cross-origin deployments: the client sends `credentials: "include"`, so the server must answer
`Access-Control-Allow-Credentials: true` with a concrete `Access-Control-Allow-Origin` (never `*`),
or the browser will drop the session cookie.

## OAuth

A provider is inert data — an authorization endpoint, a token endpoint, a client id and secret, the
scopes, and two small functions that turn what the provider hands back into an identity. It is never
a layer:

```ts
Auth.layerWithOAuth({
  // …
  providers: [
    Github.make({ clientId, clientSecret: Redacted.make(secret) }),
    Google.make({ clientId, clientSecret: Redacted.make(secret) })
  ]
})
```

`Github.makeConfig` / `Google.makeConfig` are the same constructors reading each field from `Config`,
for `Auth.layerConfigWithOAuth`.

`POST /sign-in/social` answers `{ url, redirect: true }`; navigate the browser there. The provider
returns to `GET /auth/callback/:providerId`, which consumes the state, exchanges the code, verifies
the `id_token` where the provider is an OIDC one, links or creates the account, sets the cookie and
answers a `302` to the validated `callbackURL`. A failure is a `302` to the validated error URL with
a safe code from a closed set — a provider's own error message routinely contains the authorization
code, so it is never echoed.

`Google.make({ hostedDomain: "corp.example", … })` restricts sign-in to one Workspace domain, and it
is enforced twice: the `hd` authorization parameter narrows Google's account chooser, and the `hd`
claim of the *verified* `id_token` is checked on the way back — the parameter alone is advisory,
since a caller holding the authorization URL can simply drop it.

Account linking follows better-auth's algorithm: match on `(issuer, accountId)` first; fall back to
an e-mail match only when the provider says the address is verified **and** either the provider is
in `trustedProviders` or the local account's address is already verified; otherwise create a new
user. `unlinkAccount` refuses to remove the last sign-in method.

Configure OAuth with `FetchHttpClient.layer` (or an `HttpClient` you know does not follow
redirects). The flow refuses redirects two ways — `redirect: "manual"` through the fetch options,
*and* a response check — but only the second lock applies to a non-fetch-backed client, which may
have followed a redirect internally before answering.

## Testing

```ts
import { it, assert } from "@effect/vitest"
import { Effect, Redacted } from "effect"
import { Passwords } from "effect-auth"
import { AuthTest } from "effect-auth/testing"

it.effect("signs a person up", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const emails = yield* AuthTest.TestEmails

    yield* passwords.signUp({ name: "Ada", email: "ada@example.com", password })
    yield* passwords.requestReset({ email: "ada@example.com" })

    // The token exists exactly once — in the message that carries it.
    const token = yield* emails.tokenFor("reset")
    yield* passwords.resetPassword({ token, newPassword })
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)
```

`AuthTest.layer()` is a whole deployment: a fresh in-memory PGlite database with the migrations
applied, a fixed secret, a capturing outbox, and scrypt at a cost a suite can afford. Give each test
its own layer — a `TestClock` shared across a block lets one test move time under another — and pass
`AuthTest.testTimeout`, because booting PGlite and migrating costs a few hundred milliseconds.

## Security notes

What the library does, and what it expects of you.

**Tokens.** Session tokens are 32 random bytes, base64url (43 characters). Only their SHA-256 is
stored; the raw value is returned exactly once. Verification, reset and OAuth state values are the
same. A reset or verification token is a composite `<base64url(subject)>.<secret>` so the row can be
named without a second lookup — only the secret half is hashed and stored.

**Single use.** Every consumption is one conditional `DELETE … RETURNING`, so a token cannot be
redeemed twice even under concurrent requests. An expired, an unknown and an already-used token are
all `InvalidToken`: telling them apart would require a read that reveals whether a token was ever
issued.

**Passwords.** scrypt (N=16384, r=16, p=1, dkLen=64, 16-byte salt) by default, PBKDF2-HMAC-SHA512 at
600 000 iterations where `node:crypto` is unavailable. The stored format is self-describing
(`scrypt$n=…,r=…,p=…$salt$key`), so parameters can be raised without invalidating existing hashes,
and either layer verifies either format. Digests are compared byte-wise in constant time. Policy is
8–128 characters, enforced server-side.

**No user enumeration.** Sign-in always performs exactly one hash verification, against a dummy hash
of the same shape and cost when the address is unknown or has no credential account, so the timing
does not distinguish them — and an unknown address and a wrong password answer the identical
`InvalidCredentials`. `requestPasswordReset` and `sendVerificationEmail` always answer `200`.

**CSRF.** The session cookie is `SameSite=Lax`, `HttpOnly`, and `Secure` with the `__Secure-` prefix
whenever `baseUrl` is `https:`. Only the name a deployment writes is accepted: a TLS deployment
refuses the un-prefixed cookie outright, because a network attacker on a plain-HTTP sibling origin
(or a compromised subdomain) can set that name and not the prefixed one, and honouring it would hand
back the session-fixation attack the prefix exists to stop. Cookie-authenticated requests
additionally have their `Origin` (or `Referer`) checked against `trustedOrigins`, which always
includes `baseUrl`'s origin. Bearer requests skip the check — they cannot be made by a browser on
someone else's behalf.

**Open redirects.** Every user-supplied `callbackURL` and `redirectTo` must be path-relative or have
an origin in `trustedOrigins`; anything else falls back to `baseUrl`.

**OAuth.** PKCE S256 always, no `plain` fallback. State is single-use with a ten-minute TTL and is
stored hashed. Token and user-info fetches refuse redirects. `id_token` verification is fail-closed
on issuer, audience, expiry, signature and nonce; a provider that declares an issuer but publishes
no keys fails rather than skipping verification, and the JWKS fetch refuses redirects too.

**Rate limits.** Sign-in, sign-up and `POST /sign-in/social` are 3 per 10 seconds per (IP, path);
password reset and verification mail are 3 per 60 seconds. The client IP comes from a configurable
header chain, which is only trustworthy behind a proxy you control — with `ipHeaders: []` every
request shares one fail-closed bucket, which is the safe default behind no proxy. The default
limiter is process-local: behind four instances the effective limit is four times what is
configured, so provide `RateLimiter.layer` over a shared store if that matters. When the limiter's
*store* fails — as opposed to a limit being reached — the default is to log and let the request
through, so a broken counter cannot take sign-in down with it; that trade is wrong once the store is
shared and remote, since somebody able to degrade it would silently remove all throttling, so set
`rateLimit: { failClosed: true }` there and the endpoints answer `RateLimited` instead.

**Housekeeping.** Expired sessions and verification rows are never read, but they are never deleted
either: nothing in the request path reaps them, because correctness does not depend on the row being
gone. Table size does. Run `Auth.cleanupExpired` from a scheduled job, or add `Auth.layerCleanup()`
to reap hourly inside the server process.

**Redaction.** `Headers.CurrentRedactedNames` is registered with the cookie and authorization header
names by `Auth.layer`. Add your own with `Auth.layer({ redactedHeaders: [...] })`.

**Your part.** Provide a secret with real entropy (32 bytes or more) from your secret manager, not a
literal. Serve over TLS in production so the cookie gets its `Secure` attribute and prefix. Set
`trustedOrigins` to the origins that may drive your API and nothing else. Run the migrations as a
deploy step. And read `AuthConfig`'s `cookie.name` note: it is a constant on purpose.

## Events

```ts
Stream.runForEach(Auth.events, (event) => audit(event))
```

`UserCreated`, `SignedIn`, `SignedOut`, `SessionRevoked`, `PasswordChanged`,
`PasswordResetRequested`, `EmailVerified`, `AccountLinked`, `AccountUnlinked` — every one published
after the writes it describes have committed. The hub drops rather than blocks: a stalled consumer
costs events, never a wedged sign-in, and there is no replay, so subscribe before the traffic you
care about.

## Example

`examples/basic` is a complete Node server — the auth group, one protected `GET /todos` group, a
console mailer, PGlite — with an end-to-end test that drives sign-up → verify → sign-in → protected
endpoint → change password → sign-out through the generated `HttpApiClient`. It is the integration
test bed and the source of the snippets above.

## Roadmap

v1 is authentication over sessions, credentials and OAuth. Planned next:

- **Magic links** and e-mail OTP.
- **Two-factor authentication**: TOTP, recovery codes, and a `SessionNotFresh`-style step-up guard.
- **Cookie cache**: a signed, short-lived session snapshot in the cookie (the `Hmac` service is
  already here for it) so the common request does no database read at all.
- **Redis-backed sessions** and a shared `RateLimiterStore`, for deployments where process-local is
  not good enough.
- **JWT / JWKS issuance**, for handing a verified identity to a service that is not this one.
- **Passkeys** (WebAuthn).
- **A plugin SDK**: the shape that lets a third party add endpoints, tables and events without
  forking.
- **Authorization**, as a separate package: a policy middleware that `require`s `CurrentUser` and
  `CurrentSession`, most likely Cedar-backed. Deliberately not in this one.

## License

MIT.
