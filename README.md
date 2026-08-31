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

That is the whole installation. Twenty-eight endpoints, an OpenAPI document, a typed client and a
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
  sendVerification: (e) => send(e.user.email, "Confirm your address", Redacted.value(e.url)),
  sendPasswordReset: (e) => send(e.user.email, "Reset your password", Redacted.value(e.url)),
  // The first hop of a change of address goes to the address the account has
  // now and says where it is being moved to; the second goes to the new one,
  // and is what moves it.
  sendChangeEmailConfirmation: (e) => send(e.user.email, `Confirm the move to ${e.newEmail}`, Redacted.value(e.url)),
  sendChangeEmailVerification: (e) => send(e.newEmail, "Verify your new address", Redacted.value(e.url)),
  sendDeleteAccountConfirmation: (e) => send(e.user.email, "Confirm deleting your account", Redacted.value(e.url))
})
```

Every method may fail with `EmailDeliveryError`. The endpoints that trigger them still answer `200`
regardless — whether an address has an account must not be observable — so a delivery failure is a
signal for your logs, not for the caller. The last three are only ever called by the change-email
and delete-account flows, which are off by default; a deployment that leaves them off still has to
implement them, because the interface is the same for every deployment. A plugin, by contrast, brings
a mailer service of its own rather than widening this one — see [Plugins](#plugins).

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
deploy step, and provide `Auth.layer` with a bare `SqlClient`. A deployment with
[custom user fields](#custom-user-fields) adds `Migrations.forUserFields(model)` to that record under
an id of its own.

A plugin never joins that record. `Migrations.make({ table, migrations })` gives one its own
bookkeeping table and its own ids from `0001`, sequenced with
`Plugin.Migrations.layer.pipe(Layer.provide(Migrations.layer))` — because `Migrator` orders ids
globally, so a lower id merged in later would silently never run.

Every timestamp column is `text` holding an ISO-8601 UTC string. That is portable across Postgres
and SQLite and lexicographically sortable, which is what makes the expiry predicates correct on both.
SQLite deployments must enable `PRAGMA foreign_keys = ON` for the cascade deletes.

## Endpoints

Twenty-eight, all under `/auth`. Seventeen of them carry the `Authenticated` middleware (✓) and answer
`401` without a session; six of those bypass the cookie cache in both directions (▲, see
[Cookie cache](#cookie-cache)).

**Sessions**

| Endpoint | Method / path | Auth |
|---|---|---|
| `signUpEmail` | `POST /sign-up/email` | |
| `signInEmail` | `POST /sign-in/email` | |
| `signOut` | `POST /sign-out` | ✓ |
| `getSession` | `GET /session` | ✓ |
| `listSessions` | `GET /sessions` | ✓ |
| `revokeSession` | `POST /revoke-session` | ✓ |
| `revokeSessions` | `POST /revoke-sessions` | ✓ |
| `revokeOtherSessions` | `POST /revoke-other-sessions` | ✓ |

**Credentials**

| Endpoint | Method / path | Auth |
|---|---|---|
| `requestPasswordReset` | `POST /request-password-reset` | |
| `resetPassword` | `POST /reset-password` | |
| `changePassword` | `POST /change-password` | ✓ ▲ |
| `setPassword` | `POST /set-password` | ✓ ▲ |
| `sendVerificationEmail` | `POST /send-verification-email` | |
| `verifyEmail` | `GET /verify-email?token=` | |

**The account itself**

| Endpoint | Method / path | Auth |
|---|---|---|
| `updateUser` | `POST /update-user` | ✓ |
| `changeEmail` | `POST /change-email` | ✓ ▲ |
| `confirmEmailChange` | `GET /change-email/confirm?token=` | |
| `verifyEmailChange` | `GET /change-email/verify?token=` | |
| `deleteUser` | `POST /delete-user` | ✓ ▲ |
| `deleteUserCallback` | `GET /delete-user/callback?token=` | ✓ ▲ |

**OAuth**

| Endpoint | Method / path | Auth |
|---|---|---|
| `signInSocial` | `POST /sign-in/social` | |
| `oauthCallback` | `GET /callback/:providerId` | |
| `oauthCallbackForm` | `POST /callback/:providerId` | |
| `listAccounts` | `GET /accounts` | ✓ |
| `linkSocial` | `POST /link-social` | ✓ |
| `unlinkAccount` | `POST /unlink-account` | ✓ ▲ |
| `getAccessToken` | `POST /get-access-token` | ✓ |
| `refreshToken` | `POST /refresh-token` | ✓ |

An endpoint whose feature a deployment has not switched on answers `404`: it is declared in the
contract and not served here. That is the eight credential endpoints under
`emailPassword.enabled: false`, the three change-email paths under `user.changeEmail.enabled` and
the two delete-account paths under `user.deleteUser.enabled` — the last two default to `false`, because
letting somebody move or destroy their own account is a product decision.

### The account endpoints

`updateUser` patches the fields the body names — `name`, `image`, and whichever of your own user
fields a client may write ([Custom user fields](#custom-user-fields)). An absent key leaves the
column alone; an explicit `null` image clears it. The address is deliberately not editable here.

`changeEmail` is the two-hop flow that moves it, and it always goes through the mail. It needs a
fresh session, and it answers `200` whether or not the new address is free — telling a caller that
an address is taken would make it an oracle for who is registered here. A *verified* current address
gets a confirmation link first (`confirmEmailChange`), which mails the second hop; an unverified one
skips straight to it. `verifyEmailChange` is what actually moves the account, from a link delivered
to the new address, so it ends up verified. Somebody who claimed the address between the two hops is
a `UserAlreadyExists` at the unique index. The new address travels in the token's server-side
payload and never in a URL.

`deleteUser` with `user.deleteUser.confirmByEmail` off needs a fresh session, takes the password
when the account has one, and is done: the row, its sessions and its sign-in methods are gone. With
it on, it mails a link and answers `ConfirmationSent`, and `deleteUserCallback` — which must be
followed by the account's *own* signed-in browser — finishes the job. That token is claimed first
and only then checked against the caller, so a link presented by anybody else is burnt as well as
refused.

`setPassword` gives a first password to an account provisioned through a provider. It can never
*replace* one — that is `changePassword`, or the reset flow — so an existing credential is
`PasswordAlreadySet`, including when two concurrent calls race at the unique index. It requires a
fresh session and revokes nothing: no credential was invalidated.

`getAccessToken` hands back a usable provider access token for one of the caller's linked accounts,
refreshing first only when the stored one is absent or about to expire and the provider supports it.
`refreshToken` spends the refresh token unconditionally, for a client that has already learnt the
access token is no good. An account that is not the caller's is `NotFound`, exactly as one that does
not exist. Tokens cross the wire as `Redacted<string>`; the granted `scope` is never overwritten by
a refresh.

## Custom user fields

Most applications want a column or two of their own on the person: a plan, a locale, a tenant, an
internal role. Declaring them here rather than in a table beside `users` is what makes them travel —
through sign-up, through `GET /session`, through `updateUser`, into `CurrentUser` in your own
handlers, and into the generated client's types.

Declare them once, and derive everything from the declaration:

```ts
import { Schema } from "effect"
import { HttpApi } from "effect/unstable/httpapi"
import { Auth, UserField } from "effect-auth"

export const auth = Auth.define({
  user: {
    fields: {
      // A client may state it at sign-up; the model fills it in when it does not.
      plan: UserField.withDefault(Schema.Literals(["free", "pro"]), () => "free" as const),
      // Readable everywhere, settable by nobody: yours to write, through the store.
      role: UserField.readOnly(Schema.Literals(["user", "admin"]), () => "user" as const),
      // In every database variant, in no JSON one — never in a response, a client or a cookie.
      apiSecret: UserField.hidden(Schema.NullOr(Schema.String), () => null)
    }
  }
})

export const AppApi = HttpApi.make("app").addHttpApi(auth.Api).add(MyOwnGroup)
```

`auth` carries everything that had to know: `auth.layer` (and the three other entry points),
`auth.handlers(AppApi)`, `auth.layerMigrations`, the schemas (`auth.User`, `auth.UserPublic`,
`auth.SessionWithUser`, …) and the service views (`auth.CurrentUser`, `auth.UserStore`,
`auth.Sessions`, `auth.Passwords`, `auth.Users`). Wiring is otherwise the quickstart, unchanged:

```ts
const AuthLive = auth.layer({ baseUrl, secret, emailPassword: { enabled: true } }).pipe(
  Layer.provide(auth.layerMigrations.pipe(Layer.provideMerge(PgLive))),
  Layer.provide(MyMailer)
)

const ServerLive = HttpApiBuilder.layer(AppApi).pipe(
  Layer.provide(auth.handlers(AppApi)),
  Layer.provide(AuthLive)
)
```

### What each kind means

| Constructor | At sign-up | In a response | In `updateUser` |
|---|---|---|---|
| `UserField.required(schema)` | required in the body † | ✓ | ✓ |
| `UserField.withDefault(schema, () => v)` | optional, defaulted | ✓ | ✓ |
| `UserField.readOnly(schema, () => v)` | dropped | ✓ | dropped |
| `UserField.hidden(schema, () => v)` | dropped | — | dropped |

A value a client is not allowed to state is *dropped*, not refused — the same thing Schema does with
any excess property, and the same thing better-auth does with a provider profile. So a body claiming
`role: "admin"` gets an account with `role: "user"` and a `200`.

† `required` only works when the schema carries a constructor default of its own, because of the
rule below; without one, `makeUserModel` refuses the model. Most fields want `withDefault`.

### Reading one in your own handler

```ts
Effect.gen(function*() {
  const user = yield* auth.CurrentUser   // UserOf<F> — `user.plan` is "free" | "pro"
  return user.plan === "pro" ? yield* everything : yield* theFreeSlice
})
```

`auth.CurrentUser` is the *same* context key the middleware fills, seen through your model. Nothing
in `Authenticated`'s signature, in `Auth.Services` or in any `Layer` type moved to make that work —
which is why a plugin written against `CurrentUser` still composes into your deployment.

### In the browser

```ts
import { AuthClient } from "effect-auth/client"
import { model } from "./auth-model.js"   // a browser-safe module: `makeUserModel(fields)`

const client = AuthClient.make({ api: AppApi, model })
// client.session's user is typed with `plan`; `apiSecret` is not a key on it at all
```

The model has to be stated on both sides, and `Auth.define` is deliberately not browser-safe (it
reaches the database and the hasher). Put the field map in a module of its own, call `makeUserModel`
on it for the client and hand the same map to `Auth.define` on the server.

### The one rule

**Every field must be constructible without a value.** OAuth provisioning, a magic link and any
plugin create users from the base fields alone, so a field with no default has nothing to be set to.
`makeUserModel` checks this when it builds — at module scope — and throws a message naming the
offending field, so a mistake is a start-up failure rather than a sign-in that fails in production.
In practice: use `withDefault`, `readOnly` or `hidden`, or give the schema a constructor default of
its own.

Two consequences worth knowing. A `hidden` field is absent from the cookie cache as well as from
every response, so a cached read sees its *default* — an endpoint that reads one must be annotated
`AuthoritativeSession` ([Cookie cache](#cookie-cache)). And `Migrations.forUserFields(model)` emits
the `ALTER TABLE users ADD COLUMN` for each field (`auth.layerMigrations` runs it); a type it cannot
map to a column is a `MigrationError` naming the field, and hand-written DDL is the escape hatch.

If you would rather not take the bundle, every piece is a function: `makeUserModel(fields)`,
`makeAuthApi(model)`, `AuthHandlers.layer(api, model)`, `Auth.layer({ …, user: { model } })`,
`SqlStores.layerFor(model)`, `currentUserOf(model)`. `Auth.define` is convenience over exactly
those, and calling it twice with the same fields builds two models — the same shape and *different
types*, which the compiler points out at the first call site that mixes them.

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

Three query atoms — `session`, `sessions`, `accounts` — and a mutation for every endpoint a browser
drives: `signUp`, `signIn`, `signOut`, `revokeSession`, `revokeSessions`, `revokeOtherSessions`,
`requestPasswordReset`, `resetPassword`, `changePassword`, `setPassword`, `sendVerificationEmail`,
`verifyEmail`, `updateUser`, `changeEmail`, `confirmEmailChange`, `verifyEmailChange`, `deleteUser`,
`signInSocial`, `linkSocial`, `unlinkAccount`, `getAccessToken`, `refreshToken`. The two that only a
provider or a mail client ever calls — `deleteUserCallback` and `oauthCallbackForm` — are not
wrapped.

Each mutation carries the reactivity keys of what it invalidates, so the atoms refetch themselves.
`"auth.session"` for everything that establishes, ends or edits the current session and its user
(`signUp`, `signIn`, `signOut`, `resetPassword`, `changePassword`, `verifyEmail`, `updateUser`,
`confirmEmailChange`, `verifyEmailChange`); `"auth.sessions"` for the revoke mutations and the two
that revoke everything on their way past; `"auth.accounts"` for `setPassword` and `unlinkAccount`;
all three for `deleteUser`. `signInSocialUrl(payload)` returns the provider URL to navigate to.

A deployment with its own user fields passes the model, and the atoms carry it:

```ts
const auth = AuthClient.make({ api: AppApi, model })
// auth.session's user has `plan` on it, and no `apiSecret`
```

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

Every provider has a `makeConfig` twin reading each field from `Config`, for
`Auth.layerConfigWithOAuth`.

Two providers registered under one id throw where the list is composed: an id is the `providerId` of
`POST /sign-in/social`, the last segment of the callback path and the `trustedProviders` entry all
at once, so a duplicate is a deployment where one of the two would silently never receive a
callback.

An OIDC provider carries its settings in one `oidc` block — `{ issuer, keys, audience?,
algorithms?, issuerOf? }` — whose `keys` is `{ jwksUrl }` or `{ jwks }` and is required. The
presence of the block is what makes the flow demand and verify an `id_token`; a plain OAuth2
provider has none and its accounts are stored under the synthetic issuer `local:oauth:<id>`.

A provider whose code exchange is genuinely not an OAuth2 token request can declare `exchange`,
which then owns it. It is handed the request the flow would have sent as `fallback`, so an override
that only decorates the default wraps it rather than reimplementing the exchange — and so keeps the
client-secret handling (including Apple's per-request minting) on the library's side of the seam,
where an override never sees it. It runs against the flow's own redirect-refusing client and under
the flow's own deadline, so an override that ignores `fallback` and drives the client itself still
cannot hold a callback open — the same bound a provider's whole `userInfo` gets.

### The providers

| provider | kind | identity | notes |
|---|---|---|---|
| `Github` | OAuth2 | numeric user id | `webUrl`/`apiUrl` for Enterprise Server; the address comes from `/user/emails`, and only its `verified` flag counts |
| `Google` | OIDC | `sub` | `hostedDomain` restricts sign-in to one Workspace domain, checked on the `hd` *claim* |
| `Discord` | OAuth2 | snowflake | `identify email`; `prompt` defaults to `"none"`; `Discord.avatarUrl` builds the CDN or default-avatar URL; no address (the scope was refused) is a refusal |
| `Gitlab` | OAuth2 | numeric user id | `baseUrl` points at a self-hosted instance; an account that is not `active`, or is `locked`, is refused |
| `Microsoft` | OIDC | `oid` | Entra ID; `tenantId` (`"common"` by default) and `authority`; `clientSecret` is optional for a public PKCE client |
| `Apple` | OIDC | `sub` | Sign in with Apple; the client secret is minted per token request from the `.p8` key |
| `OidcDiscovery` | OIDC | `sub` | any provider that publishes `.well-known/openid-configuration` |

**Microsoft** is the multi-tenant case. `common`, `organizations` and `consumers` cannot pin an
issuer, so the expected one is derived from the token's own `tid` claim and compared with `iss`, a
personal account is refused under `organizations` and required under `consumers`, and the account is
stored under the per-tenant issuer the verified token named. The identity is `oid` — Entra's `sub` is
per application — and `emailVerified` is `false` unless the optional `email_verified` claim was
configured or Entra's own verified-address list names the address.

**Apple** needs a Services ID, a team id, a key id and the `.p8` signing key:

```ts
Apple.make({
  clientId: "com.example.web",
  teamId: "ABCDE12345",
  keyId: "FGHIJ67890",
  privateKey: Redacted.make(process.env.APPLE_PRIVATE_KEY!)
})
```

The client secret is a short-lived ES256 assertion, minted afresh for every token request rather than
configured; `Apple.makeConfig` mints one at build time, so a broken key fails the boot instead of
somebody's first sign-in. Asking for the `name` scope makes Apple `POST` the callback cross-site,
which `POST /auth/callback/:providerId` answers with a `302` to its `GET` twin — a cross-site POST
carries no `SameSite=Lax` cookie, so the flow has to complete on the top-level navigation. The name
Apple posts there arrives once, is unsigned, and is used for the display name and nothing else. A
native application whose tokens name its bundle identifier passes `appBundleIdentifier`, or
`audience: [servicesId, bundleId]` to accept both.

**Any other OIDC provider** — Auth0, Okta, Keycloak, Zitadel, your own identity server — is one
`OidcDiscovery.make`:

```ts
Auth.layerConfigWithOAuth({
  // …
  providers: [
    Effect.flatMap(
      Config.redacted("OIDC_CLIENT_SECRET"),
      (clientSecret) =>
        OidcDiscovery.make({ id: "acme", issuer: "https://id.acme.test", clientId, clientSecret })
    )
  ]
})
```

Discovery runs once, while the stack is built, so a provider that cannot be discovered fails the boot
with a `DiscoveryError` naming the reason (`Unreachable`, `Malformed`, `IssuerMissing`,
`IssuerMismatch`, `EndpointsMissing`, `KeysMissing`). The document must declare the very issuer that
was configured, the fetch refuses redirects like every other outbound OAuth request, a document with
no `jwks_uri` and no pinned key set is a failure rather than a skipped signature check, and only the
asymmetric entries of the advertised algorithm list are admitted. Anything stated in the options wins
over the document, so a gateway that rewrites one endpoint does not cost you discovery of the rest.

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

## Cookie cache

Every authenticated request reads the session and its user in one query. The cookie cache removes
even that: beside the session cookie the server writes a second, short-lived cookie carrying a
**signed snapshot** of exactly what `GET /auth/session` answers with, and a request presenting a
valid snapshot is served with **no database read at all**.

It is off by default. Switch it on per deployment:

```ts
const AuthLive = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make(process.env.AUTH_SECRET!),
  cookieCache: {
    enabled: true,
    maxAge: Duration.minutes(5),  // the default, and the revocation lag below
    version: ""                   // bump to invalidate every outstanding snapshot
  }
})
```

The value is `base64url(json) + "." + base64url(HMAC-SHA-256(secret, json))`, written under
`effect_auth.session_data` (`__Secure-`-prefixed on TLS, with the session cookie's own attributes).
The signed payload carries the session, the user's public projection, a version string, the
snapshot's expiry, and the SHA-256 of the session token it was minted for. Reading it verifies the
tag, checks that digest against the credential actually presented, then the expiry and the version.
Every failure — a tampered payload, another deployment's secret, a snapshot from another browser, an
unreadable value — is a *miss*, which reads the database as before. It is never a `401`.

A snapshot expires at `min(now + maxAge, refreshDueAt(session), session.expiresAt)`. Clamping to the
refresh instant is what keeps the rolling session refresh honest: the first request after a session
becomes refresh-due misses the cache, rolls the expiry forward and re-sends both cookies. Nothing
here ever re-signs or extends a session.

**What you are trading.** Read this before switching it on.

- **Revocation lag.** A session revoked in one browser keeps working in another for up to `maxAge`,
  because a valid snapshot means no database read. The same holds for a user row that changed
  elsewhere. `maxAge` is exactly the size of that window; a deployment that cannot accept it
  anywhere leaves the cache off.
- **Integrity, not confidentiality.** The payload is signed, not encrypted — anyone holding the
  cookie can read it. It contains only what the endpoint would have answered with, which is why a
  `UserField.hidden` column is absent from it and why nothing secret may ever be added.
- **A hidden field is not carried.** A cached read sees a `UserField.hidden` field's declared
  default, not its stored value. An endpoint that reads one must be annotated (below).
- **It is not a defence.** Rotating `secret` invalidates every outstanding snapshot, but that is
  mass *cache* invalidation, not sign-out: the session tokens themselves are untouched.
- **Bearer clients gain nothing.** The cache is written and read on the cookie transports only. A
  header-only client has no jar, and letting a cookie decide what such a request sees is exactly
  what must not happen.

Endpoints whose decision depends on the *current* row bypass the cache in both directions —
`changePassword`, `setPassword`, `unlinkAccount`, `changeEmail`, `deleteUser` and
`deleteUserCallback`. Your own endpoints opt in the same way, with one line and no second
middleware:

```ts
const rotateKeys = HttpApiEndpoint.post("rotateKeys", "/rotate-keys", { success: Ok })
  .middleware(Authenticated)
  .annotate(AuthoritativeSession, true)
```

Signing out, revoking every session, resetting a password and deleting an account clear *both*
cookies: clearing only the session cookie would leave a snapshot behind, and a snapshot is served
without a database read. `version` bumps everything at once — pass a function
(`(session, user) => string`) to make invalidation sensitive to something about the principal, such
as a tenant or a role, remembering that it runs on the snapshot's own contents and on the hot path.

### Swapping the session store

`sessionStore` is the other half of the same subject: a layer laid *over* the SQL stores, provided
them (so it may delegate) and merged above them (so what it publishes is the `SessionStore` every
service resolves). It is the seam a distributed store — Redis, or anything else — plugs into, and
the one place where "the store" and "the SQL store" can differ. The other three stores are
deliberately not decorable: nothing in this library reads them on a hot path.

```ts
const Cached = Layer.effect(
  Stores.SessionStore,
  Effect.map(Stores.SessionStore, (inner) => ({
    ...inner,
    findByTokenHash: (hash: string) => readThrough(hash, inner.findByTokenHash(hash))
  }))
)

const AuthLive = Auth.layer({ ..., sessionStore: Cached })
```

`AuthTest.countingSessionStore()` is the same seam in the test harness, and is how this repository's
own suite asserts that a cache hit performs zero reads.

## Hooks

Six moments at which this library asks *your* code whether to proceed — and, at one of them, what
the row should say. They are how a deployment refuses a sign-up, derives a `role` from an OAuth
profile, or writes a tenant row atomically with the user it belongs to.

```ts
import { Auth, Hooks } from "effect-auth"

const Policy = Hooks.layer({
  beforeUserCreate: ({ candidate, source }) =>
    candidate.email.endsWith("@acme.com")
      ? Effect.succeed(candidate)
      : Effect.fail(new Hooks.PolicyRefused({ code: "domain_not_allowed" })),
  afterUserCreate: ({ user }) => Memberships.create({ userId: user.id })  // same transaction
})

const AuthLive = Auth.layer(options).pipe(Layer.provide(Policy), Layer.provide(PgLive))
```

| Hook | Asked | May |
|---|---|---|
| `beforeUserCreate` | before any user row is written, whatever created it | rewrite the candidate, or refuse |
| `afterUserCreate` | once the row exists, in the same transaction | write the rows that hang off it, or refuse |
| `beforeSessionCreate` | before a session is minted, after the credential was verified | refuse |
| `beforeEmailChange` | before an address change starts, ahead of any token | refuse |
| `beforeUserDelete` | on both shapes of account deletion, after the caller proved who they are | refuse |
| `beforeAccountLink` | before a provider identity is attached to a user that already exists | refuse |

Every member is optional and absent means "allow, unchanged", so installing nothing is the default
and costs nothing. `source` tells `beforeUserCreate` which door the person came through —
`EmailPassword`, `OAuth` (carrying the verified profile, so one hook covers every provider),
`MagicLink`, or a plugin naming itself — which is what lets one policy cover every flow you serve.
The candidate always arrives complete: your own columns are filled in from the model's declared
defaults before the hook is asked, on every source, so a policy reads the same row whichever door
the person came through. A rewrite is re-validated through the user model, so a hook cannot store a
row the schema rejects, and an address a hook rewrote is normalized on the way in — every lookup in
this library reads a user by the normalized address, so one stored otherwise would be a row nothing
could find again.

A plugin installs hooks by **appending**, never replacing, because it cannot know what else you
installed:

```ts
const PluginPolicy = Hooks.append({ beforeSessionCreate: refuseIfSuspended })
```

Whatever is already there runs first, each `beforeUserCreate` sees what the one before it answered,
and the first refusal ends the chain — so your refusal short-circuits a plugin's hook, and a plugin
never silently disables your policy.

**Three rules.** They are the whole of what you need to hold in your head:

1. **Hooks are short and local.** Every one of them runs inside the transaction the flow holds, so a
   hook that makes a network call is holding a database transaction open across it. Anything slow,
   retryable or merely interesting belongs on `Auth.events`, which is fire-and-forget and runs after
   the commit.
2. **`PolicyRefused` is the only failure you may raise.** Anything else your hook throws or dies with
   is a defect and renders as an opaque `500` — which is the correct answer for a broken policy.
3. **A ban enforced by `beforeSessionCreate` does not touch live sessions.** It refuses *new* ones.
   Pair it with revocation, or with `cookieCache.version` keyed on a **public** field — never a
   hidden one, for the reason the cookie-cache section gives.

`code` is yours, and it is shown to the caller verbatim: in a `403` body, and in a URL a browser is
redirected to. Make it a short stable classification a client can branch on — `"banned"`,
`"domain_not_allowed"` — and never put a secret, another person's data, or the internals of the
policy in it. `detail` is under the same rule.

How a refusal reaches the caller depends on the shape of what it refused. `signUpEmail`,
`signInEmail`, `signInSocial`, `linkSocial`, `changeEmail`, `deleteUser` and the magic link's
`exchange` answer the typed `403`. The completions a browser arrives at by a top-level navigation —
the OAuth callback, a magic link, the delete-account link — have nowhere to put an error, so they
redirect carrying `?error=policy_refused&code=<yours>`, to the same error URL every other failure of
that flow lands on when the flow has one in hand; a link is spent either way, because the hook is
asked after the token has been claimed. And one case is neither: refusing the session a **sign-up**
would have started leaves the account in place and answers `200` with `session: null`, exactly as
`autoSignIn: false` does — the person was accepted, they simply cannot start a session.

If you declared custom user fields, `Hooks.hooksOf(model)` is the same slot with `candidate` and
`user` typed by your model, so a hook reads and writes your own columns with no cast:

```ts
const Policy = Layer.succeed(Hooks.hooksOf(model))({
  beforeUserCreate: ({ candidate }) =>
    Effect.succeed({ ...candidate, role: candidate.plan === "pro" ? "admin" : "user" })
})
```

## Plugins

A plugin is a module, not a registration. There is no plugin object, no `plugins: [...]` array and
no lifecycle: a feature that adds endpoints exports the same four things this library's own core
does, and a consumer composes them with plain layers.

| Export | What it is |
|---|---|
| `XApiGroup` | an `HttpApiGroup`, browser-safe, with its own `/auth/<kebab>` prefix |
| `layer(options)` | its domain service, over whatever `Auth.layer` published |
| `handlers(api)` | `AuthHandlers.forGroup(XApiGroup, …)` — applied to *your* composed API |
| `XClient` (optional) | a browser client, and a testing module beside it |

```ts
const AuthLive = Auth.layer(options).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))

const MagicLinkLive = MagicLink.layer({ ttl: Duration.minutes(10) }).pipe(
  Layer.provideMerge(AuthLive),          // the plugin reads the deployment's own services
  Layer.provide(MyMagicLinkMailer)       // …and one seam of its own
)

const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLink.MagicLinkApiGroup).add(Todos)

const HandlersLive = Layer.mergeAll(
  AuthHandlers.layer(AppApi),
  MagicLink.handlers(AppApi),
  Todos.layer
).pipe(Layer.provide(MagicLinkLive))
```

`AuthHandlers.forGroup(group, build)` is what makes the third line possible. `HttpApiBuilder.group`
takes the API a group was *added to*, and a library cannot name the API you will compose — so a
plugin calling it directly would either fix its consumers to one API or repeat this library's
boundary cast. `forGroup` is that boundary, written once: hand it your group and your handlers, and
what comes back is a function you apply to your own API. The API's `groups.<id>` is pinned to the
group you passed, so an API carrying a *different* group under the same name is a compile error
rather than a mis-served route.

The rest of the seams a plugin uses:

- **Tokens.** `Verifications.purpose(name, payloadSchema?)` declares a class of single-use tokens;
  `issue` / `claim` / `retire` do the rest. The row is namespaced `"<purpose>:<subject>"`, only the
  digest is stored, and the payload is server-side state — put a callback URL in one, never a
  credential.
- **Errors.** Your own `Schema.TaggedError`s with `httpApiStatus`. `AuthHandlers.dieOn(tags)` keeps
  your infrastructural failures out of your endpoints' error unions, exactly as `serverFault` keeps
  this library's two out of its own.
- **Mail.** A service of your own in your `Requirements`, not a method on `AuthEmails`: a plugin
  cannot widen an interface every deployment implements, and the shapes differ (a magic link may
  have no user behind the address). Forgetting it is a compile error.
- **Events.** `PluginEvent { plugin, event, userId, data }` on the closed `AuthEvent` union. No
  secrets in `data` — events reach log sinks and webhooks.
- **Tables.** `Migrations.make({ table, migrations })` gives a plugin its own bookkeeping table and
  its own ids from `0001`. Never merge a plugin's migrations into this library's record: the migrator
  orders globally, so a lower id added later never runs.
- **Users.** Provision through `Users.provision`, not `UserStore.create`: it is where the
  deployment's `beforeUserCreate` / `afterUserCreate` hooks are consulted, and going through it is
  what keeps them one choke point rather than one per flow. Build the row from the base user fields
  alone — the deployment's own custom columns are filled in from the model's declared defaults,
  which is what the provisionability rule on `makeUserModel` guarantees.
- **Testing.** `AuthTest.layerHttpApi(api, options, extra)` provides your handler layer the *same*
  deployment build the auth handlers get, so both groups read one `Sessions` and one rate limiter.
  `TestEmails.record` is the seam your mailer's test layer implements over.

### Magic link

The first plugin, and the worked example of all of the above. Passwordless sign-in by a single-use
link. It owns no table — a link is a `Verifications` token — so a deployment that has run this
library's migrations needs no new ones.

| Endpoint | Method / path |
|---|---|
| `signIn` | `POST /auth/magic-link/sign-in` |
| `verify` | `GET /auth/magic-link/verify?token=` |
| `exchange` | `POST /auth/magic-link/exchange` |

```ts
MagicLink.layer({
  ttl: Duration.minutes(5),        // how long a link may be followed for
  disableSignUp: false,            // refuse an address that has no account
  path: "/auth/magic-link/verify", // where the e-mailed link points
  revokeUnprovenAccounts: true     // the takeover defence below
})
```

`signIn` answers `200` for every well-formed address — one with an account, one without, and one
whose message could not be delivered — because a distinguishable answer would tell an
unauthenticated caller who is registered here. `verify` is for the browser: it claims the token,
sets the session cookie and redirects, and it redirects on failure too, to the link's own
`errorCallbackURL` carrying `?error=invalid_token` or `?error=sign_up_disabled`. `exchange` is the
JSON twin for a single-page or mobile client, and sets the cookie as well.

The callback URLs travel in the token's server-side payload rather than in the link, so a link
cannot be edited into a link that lands somewhere else; each of them is validated against
`trustedOrigins` when the link is minted, and dropped rather than refused if it does not survive
that. A link created the account when it is followed? Then `newUserCallbackURL` wins over
`callbackURL`.

**The unproven-account rule.** Somebody can register an address they do not own, wait, and hope its
real owner later signs in with a magic link — they would then share the account. So when a link
proves control of an address whose account is *unverified*, that account's sign-in methods and
sessions are destroyed in one transaction and the address is marked verified. Switching
`revokeUnprovenAccounts` off keeps the address verification and keeps the squatter's password: do it
only if something else in the deployment guarantees no account is ever created unverified.

The mailer is one method:

```ts
const MyMagicLinkMailer = Layer.succeed(MagicLink.MagicLinkEmails)({
  sendMagicLink: ({ email, user, token, url }) =>
    send(email, user === null ? "Create your account" : "Sign in", Redacted.value(url))
})
```

`user` is `null` when the address has no account. Both messages must go out, and a delivery failure
is logged and swallowed — the endpoint answers `200` either way.

In the browser, `MagicLinkClient` is a client of its own, so an application that does not serve magic
links never ships it:

```ts
import { MagicLinkClient } from "effect-auth/client"

const magicLink = MagicLinkClient.make({ baseUrl: "https://app.example.com" })

registry.set(magicLink.signIn, { email, callbackURL: "/welcome" })
// …and, from the page the link lands on:
registry.set(magicLink.exchange, { token: Redacted.make(tokenFromTheUrl) })
```

It takes no `api` option: the group's prefix is baked into its declaration, so the paths it calls are
the ones your composed API serves. `exchange` carries `"auth.session"`, so an `AuthClient` built
beside it refetches its session atom by itself. If you would rather drive your own composed API,
`HttpApiClient.group(AppApi, { group: "magicLink" })` needs nothing from this library at all.

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

**Cookie cache.** Off unless a deployment asks for it. When it is on, an authenticated request may
be served from a signed snapshot rather than from the database, which buys a request with no reads
and costs a revocation lag of at most `cookieCache.maxAge`. The full trade — including why the
snapshot is signed but not encrypted, and which endpoints bypass it — is in
[Cookie cache](#cookie-cache) above.

**OAuth.** PKCE S256 always, no `plain` fallback. State is single-use with a ten-minute TTL and is
stored hashed. Token and user-info fetches refuse redirects. `id_token` verification is fail-closed
on issuer, audience, expiry, signature and nonce; a key set that cannot be read fails rather than
skipping verification, a provider that declares OIDC settings and no key source cannot be written
down at all, and the JWKS fetch refuses redirects too. A provider's whole `userInfo` is bounded by a
thirty-second deadline the provider cannot opt out of, and two providers registered under one id
refuse to build.

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
`PasswordResetRequested`, `EmailVerified`, `UserUpdated`, `EmailChanged`, `UserDeleted`,
`TokensRefreshed`, `AccountLinked`, `AccountUnlinked`, and `PluginEvent` — every one published after
the writes it describes have committed. The hub drops rather than blocks: a stalled consumer costs
events, never a wedged sign-in, and there is no replay, so subscribe before the traffic you care
about.

The union is closed, so a plugin publishes `PluginEvent { plugin, event, userId, data }` rather than
a member of its own. No event carries a token, a password, a hash or a provider credential — events
routinely end up in log sinks and webhooks, and `data` is held to the same rule.

## Example

`examples/basic` is a complete Node server in six files — the auth group carrying a deployment's own
`plan` field, the magic link plugin, one protected `GET /todos` group of its own, two console
mailers, PGlite. Its end-to-end test drives sign-up → verify → sign-in → protected endpoint →
change password → sign-out, the reset flow, `update-user` on the custom field, `set-password` for an
account that has none, and a magic link that provisions the account it names — all through the
generated `HttpApiClient`. It is the integration test bed and the source of the snippets above.

## Roadmap

Shipped since v1: the [plugin seams](#plugins) and [magic link](#magic-link) on top of them, the
account endpoints (update, change-email, delete, set-password) and OAuth token refresh, four more
providers plus [OIDC discovery](#the-providers), the [cookie cache](#cookie-cache), and
[custom user fields](#custom-user-fields).

Planned next:

- **E-mail OTP**, the other passwordless shape, as a second plugin.
- **Two-factor authentication**: TOTP, recovery codes, and a `SessionNotFresh`-style step-up guard.
- **Passkeys** (WebAuthn).
- **Redis-backed sessions** and a shared `RateLimiterStore`, for deployments where process-local is
  not good enough. The [`sessionStore` seam](#swapping-the-session-store) is what the first plugs
  into.
- **JWT / JWKS issuance**, for handing a verified identity to a service that is not this one.
- **Encryption at rest for provider tokens.** They are stored as the provider issued them today,
  which is a known gap rather than a decision.
- **Organizations / multi-tenancy**, most likely as a plugin over the same seams.
- **Authorization**, as a separate package: a policy middleware that `require`s `CurrentUser` and
  `CurrentSession`, most likely Cedar-backed. Deliberately not in this one.

## License

MIT.
