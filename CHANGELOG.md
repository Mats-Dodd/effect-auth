# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Nothing has been published to a registry yet, so everything below is unreleased and will fold into
the first tag. Nothing here is a breaking change *to a consumer*, because there are no consumers —
the entries are recorded so the first release notes can be written from something other than a diff,
and "breaking" below means what a consumer would have had to change had there been one.

## [Unreleased]

### Tagged unions on Effect primitives (2026-09-02)

Every hand-rolled `_tag` in `src/` — union types spelled member by member, `{ _tag: "X", ... }`
literals, `value._tag === "X"` checks, `Extract<E, { readonly _tag: … }>` derivations — now goes
through the primitive `effect@4.0.0-rc.112` ships for it: `Data.taggedEnum` for in-memory unions,
`Schema.TaggedStruct` / `Schema.toTaggedUnion` for wire unions, `Result` for success-or-failure
values, `Effect.catchTag` / `catchReason` / `Match.tagsExhaustive` for branching, and
`Types.ExtractTag` / `Types.Tags` for derived types. **No tag value changed.** Every wire encoding
and the OpenAPI document are byte-identical; the residual `_tag` spellings in `src/` are generic
constraints, `toTaggedUnion("_tag")` calls, and doc lines about `"_tag" in result`. SPEC.md
Amendment 20 records the design decisions and the three places rc.112's types forced a fallback.

#### Breaking

- **`OriginCheck.RedirectFailure<E>` no longer carries `_tag: "Failure"`**, and
  `OriginCheck.redirectFailure(config, errorCode)` now produces
  `Result.Result<never, RedirectFailure<E>>`. A redirect-shaped completion *is* a `Result`: branch
  with `Result.isSuccess` / `Result.isFailure` / `Result.match`, read `.success` / `.failure`.
- **`OAuthFlow.complete` answers `CallbackOutcome = Result.Result<CallbackResult,
  RedirectFailure<CallbackError>>`** instead of a hand-rolled `Success`/`Failure` union.
  `CallbackResult`'s fields are unchanged.
- **`EmailOtp.follow` answers `LinkOutcome = Result.Result<SignedIn | Challenged,
  RedirectFailure<VerifyError>>`** instead of a three-armed union with an inline failure arm.
- **`EmailOtp.VerifyResult` is a `Data.TaggedEnum`** with a value of the same name carrying
  `SignedIn`, `Challenge`, `Verified`, `PasswordReset`, `$is` and `$match`. `SignedIn`,
  `Challenged`, `Verified` and `PasswordReset` are still exported and structurally unchanged, but
  are `Data.TaggedEnum.Value<VerifyResult, …>` aliases rather than standalone interfaces.
- **`EmailOtp.EmailOtpSignedIn`, `EmailOtpVerified`, `EmailOtpPasswordReset` are
  `Schema.TaggedStruct`s** (`.make` fills `_tag`), and `EmailOtpResult` is a
  `Schema.toTaggedUnion` gaining `.cases`, `.guards`, `.isAnyOf`, `.discriminants`, `.match`,
  `.matchOrElse`. Encoding unchanged.
- **`Passkeys.PasskeyAuthentication`, `TwoFactor.Factor`, `TwoFactor.ChallengeSubject` are
  `Data.TaggedEnum`s**, each with a value of the same name beside the type (constructors, `$is`,
  `$match`). Member shapes and tag values are unchanged, so an existing literal still typechecks.
- **`AuthClient.withStepUp`'s `onStepUp` parameter is `Types.ExtractTag<E, "StepUpRequired">`**
  rather than a hand-written `Extract<…>`. The same type for every literal-tagged union (and every
  union in this tree is one); `ExtractTag` additionally matches a member whose `_tag` is `string`.
  The emitted `.d.ts` text changes.
- **`AuthTest.tagsOf` is generic in its element type**
  (`<E extends { readonly _tag: string }>(values: ReadonlyArray<E>) => ReadonlyArray<string>`).
  Every existing call compiles; the answer is still `ReadonlyArray<string>`.

#### Added

- `Hooks.ProvisionSource` **value**: `EmailPassword()`, `OAuth({ providerId, info })`,
  `MagicLink()`, `Plugin({ plugin })`, `$is`, `$match`. The type is now the `Data.TaggedEnum`
  with the same four members; existing literals still typecheck.
- `SignIn.SignInDecision` **value** (`Proceed()`, `Challenge({...})`, `$is`, `$match`);
  `SignIn.SignInChallenge` is now `Data.TaggedEnum.Value<SignInDecision, "Challenge">`, one
  declaration for the shape. `SignIn.proceed` is unchanged.
- `SignIn.SignInComplete<F>` (the `Complete` member of `SignInResult<F>`, previously anonymous)
  and a `SignIn.SignInResult` **value** with `Complete`, `Challenge`, `$is`, `$match`. Hand-written
  rather than `Data.taggedEnum`, because the enum cannot carry a constrained generic (Amendment 20.2).
- `AuthEvents.AuthEvent` is a `Schema.toTaggedUnion("_tag")` union: `.cases`, `.guards`,
  `.isAnyOf`, `.discriminants`, `.match`, `.matchOrElse`. Decoding and encoding unchanged.
- `MfaRequired.make({ available, expiresAt })` is how a `202` body is built; its declaration is
  unchanged (a `Schema.Struct` with a `Schema.tag`, so the field docs survive into the `.d.ts`).
- `AuthHandlers.setPendingCookieFor(config, challenge)` writes the pending-authentication cookie
  for a `SignInChallenge` for as long as the challenge lives, and
  `AuthHandlers.mfaRequired(config, challenge)` does that and returns the `202` body. Together they
  replace the copy-pasted `Challenge` branch in six sign-in handlers and the two redirect-shaped
  ones (OAuth callback, e-mail link), so the pending-cookie lifetime is computed in one place.
- `Stores.persistenceFailureKind(cause)`, the single classifier of a driver failure into
  `PersistenceFailureKind` (replacing five identical private copies), and
  `Stores.isUniqueViolationFailure(error)`, a refinement for a retry `while:`.

#### Changed — no API change

- `AuthHandlers.dieOn` / `serverFault` signatures use `Types.ExtractTag`; the computed error
  channel is the same set for every literal-tagged union. Their test is built from
  `Predicate.isTagged`.
- `OAuthFlow.errorCode` and `EmailOtp.errorCode` are built with `Match.tagsExhaustive`; the
  private mapped types over `E["_tag"]` are gone. A new union member is still a compile error.
- `OAuthFlow.complete`, `EmailOtp.follow`, `Passwords.signUp` and the passkeys session lookup no
  longer materialise inner effects with `Effect.result`: they `catchTag` the failures they handle,
  so a `PersistenceError` propagates with the `Cause` it was raised with instead of being re-failed.
  Declared types unchanged.
- `RateLimits` classifies a limiter failure with `Effect.catchReason("RateLimiterError",
  "RateLimitExceeded", …)`; same two outcomes, same `retryAfterSeconds`, same fail-closed behaviour.
- The session middleware's verify path rewrites only `SessionExpired` into `Unauthorized`; an
  `Unauthorized` raised by `Sessions.verify` reaches the caller as the original value. Both encode
  identically (`Unauthorized` carries no fields).
- `Provider.ts`'s transport retry predicate is `Filter.reason("HttpClientError", "TransportError")`.
- Every `AuthEvent` published anywhere is built with its `Schema.TaggedStruct` constructor, every
  `ProvisionSource` with its constructor, and the anonymous, passkeys, phone, username and SQL
  stores classify failures through `Stores.persistenceFailureKind`. Encodings byte-identical.
- Doc comments that said "branch on `_tag`" now name the primitive (`AuthEvent.match`,
  `Match.tagsExhaustive`, `ProvisionSource.EmailPassword`). The client docs that say
  `"_tag" in result` stay: the other arm of those unions is untagged.

The Phase 1 wave (human authentication — session assurance, a single sign-in choke point, and seven
plugins) is recorded first, breaking items ahead of additions. SPEC.md Amendment 19 has the
reasoning; this file has the call sites. Everything below that is the earlier tightening pass.

### Removed — breaking

- **The magic link plugin is gone.** `src/magic-link/`, `MagicLinkClient` and `MagicLinkTest` are
  deleted, and with them `POST /auth/magic-link/sign-in`, `GET /auth/magic-link/verify` and
  `POST /auth/magic-link/exchange`. `MagicLink`, `MagicLinkApiGroup`, `MagicLinkApi`,
  `MagicLinkEmails`, `magicLinkPurpose`, `magicLinkEvidence`, `magicLinkMethod`, `magicLinkPlugin`
  and `mfaRequiredCode` go with them, and nothing this library ships produces
  `ProvisionSource.MagicLink` any more.

  **`EmailOtp` replaces it**, link and all: `GET /auth/email-otp/link?token=` is the same
  single-use link, backed by the same `verifications` row as the code beside it. See SPEC
  Amendment 19.9 for the mapping, including why there is no `signUp` purpose and no `exchange`.

- **`SessionNotFresh` is removed**, from the error surface and from the wire. `StepUpRequired`
  (403, `{ required, current }`) replaces it on `changePassword`, `unlinkAccount`, `changeEmail`,
  `deleteUser` and `setPassword` — and, because it is declared on the `Authenticated` middleware,
  it now appears on **every** authenticated endpoint's error union and OpenAPI 403.

- **`requireFresh` is removed** from `Sessions` and from `http/Middleware`. The replacements are the
  `RequireAssurance` endpoint annotation and `Sessions.requireAssuranceFor` /
  `Sessions.requireAssurance`; `{ maxAge: config.session.freshAge }` is the old behaviour exactly.

- **`Passwords.SignInResult` is deleted.** `PasswordsService.signIn` answers `SignIn.SignInResult`.

### Changed — breaking

- **`Session` carries how it was authenticated.** Three new fields in every variant, `json`
  included, so `GET /auth/session` and `/auth/sessions` bodies change:

  ```diff
    {
      "id": "…", "userId": "…", "expiresAt": "…", "rememberMe": true,
  +   "authenticatedAt": "2026-09-01T00:00:00.000Z",
  +   "aal": "aal1",
  +   "methods": "[{\"method\":\"password\",\"factor\":\"knowledge\",…}]"
    }
  ```

  `methods` is a JSON **string** on the wire, matching the stored column, because the cookie cache
  reconstructs a session from `Session.json` through the stored schema — the `accounts.scope`
  precedent. Every outstanding cache snapshot misses once, which is safe (SPEC §16.2).

- **`POST /auth/sign-in/email` answers a two-status union.** 200 `SessionWithUser`, or 202
  `MfaRequired { _tag, available, expiresAt }` when a factor plugin owes a second factor. The 202
  sets `__Host-effect_auth.pending` and never a session cookie, and carries no user id, address or
  token. A deployment with no factor plugin is byte-identical to 0.1.0. `POST /auth/username/sign-in`,
  `POST /auth/phone/sign-in/verify`, `POST /auth/email-otp/verify` and
  `POST /auth/passkeys/authenticate/verify` answer the same union.

  ```diff
  - const { user, session } = yield* client.auth.signInEmail({ payload })
  + const result = yield* client.auth.signInEmail({ payload })
  + if ("_tag" in result) return promptForSecondFactor(result.available)
  + const { user, session } = result
  ```

- **Core's unauthenticated POSTs check the origin.** `signUpEmail`, `signInEmail`,
  `requestPasswordReset` and `sendVerificationEmail` now call
  `OriginCheck.requireTrustedIfPresent` and declare `OriginNotAllowed` (403): a present-and-untrusted
  `Origin` or `Referer` is refused, one that is absent passes. Wire-visible on all four, and it
  brings core into line with every plugin door.

- **`POST /auth/delete-user` is guarded on every path**, including `user.deleteUser.confirmByEmail`
  with no password, where a stale session could previously ask for the confirmation mail.

- **`Sessions.create` is renamed `Sessions.createUnchecked`**, and gains optional `methods`, `aal`
  and `authenticatedAt`. It consults no hook, no pipeline and publishes no event, so the name says
  what it is; `SignIn.complete` is its only sanctioned caller and a test pins that `src/` calls it
  once.

  ```diff
  - const { session, token } = yield* sessions.create({ userId, rememberMe })
  + const result = yield* signIn.complete({ user, source, evidence, current, request })
  ```

- **`SessionsService` and `SessionStoreService` gain `elevate`.** The store's takes an `append`
  callback rather than a finished array and hands it the log *as stored*, under the row lock, so a
  caller holding a stale `Session` value cannot drop what the row learned in between. A replacement
  store must implement it that way.

- **`AuthHooks` gains a second session hook, and both gain `current`.** `beforeSessionCreate` asks
  *may this person sign in at all* and runs before the `SignInPipeline`; the new
  `beforeSessionMint` asks *what has to happen as this session is minted* and runs after the
  pipeline has said `Proceed`. Work that must not happen for a sign-in that never completes — a
  merge, a `DELETE` of the account being merged away — belongs in the second, which is where the
  anonymous plugin's merge hangs. Both contexts gain `current: Option<SessionWithUser>`; a hook
  written as a destructuring arrow keeps compiling, one typed against the old object literal does
  not.

- **`AuthEvent` gains `SessionElevated { userId, sessionId, method }`, and `SignedIn` gains
  `methods`.** An exhaustive match over the union must add both.

- **`AuthConfigService` gains `assurance.stepUpWindow`** (default 12 h). A hand-constructed
  configuration must supply it, exactly as it must `trustedOriginSet`. `AuthConfigOptions`,
  `Auth.Settings` and `Auth.ConfigSettings` gain the matching optional section, and
  `AuthConfig.defaultAssurance` is exported.

- **`OAuthProviderConfig.emailVerified` is required** (`"derived" | "never"`). Every hand-written
  provider value and every `OidcDiscovery.make` call must state one
  (`OidcDiscovery.Options.emailVerified` defaults to `"derived"`). `makeRegistry` puts every
  provider through `applyEmailVerifiedPolicy`, so a `"never"` provider's identity always carries
  `emailVerified: false` and can never *implicitly* link onto a local account holding the same
  address.

- **`OAuthFlow.CallbackResult` gains `challenge`**; when it is present `session` and `token` are
  `null`. `OAuthFlow.make`/`layer` no longer require `Sessions` — they require `SignIn`.

- **`Accounts.unlink` counts authenticators as well as accounts**, and no longer counts a
  `local:credential` row that carries no hash. A user with one provider row and a hashless
  credential row can no longer unlink themselves into a lockout.

- **`Passkeys.remove` refuses `CannotRemoveLastAuthenticator` (409)** when the credential is the
  account's only way in — the mirror of the guard on unlinking the last account. A passwordless
  account could previously delete its only passkey and be locked out.

- **The two-factor factor-management endpoints ask for a method, not a level.** `totp/disable` and
  `recovery/regenerate` carry `TwoFactor.provedSecondFactor` — `{ methods: ["totp",
  "recoveryCode"] }` — in place of `{ aal: "aal2" }`, which an account whose only first factor is
  possession can never reach. A session that reached `aal2` without answering *this* plugin's factor
  no longer passes them. SPEC 19.6.

- **`TwoFactor.layer` runs the trusted-device sweep itself.** The revoke-on matrix (password change
  or reset, address change, sign-out-everywhere) is a live subscription forked into the plugin's
  scope rather than a recipe a deployment had to wire. `Phone.Options.stepUp` now defaults to
  `false`, like `signIn`, and turning it on turns `requireAlternateSecondFactor` on with it unless
  that is stated.

- **`TokenService` gains `generateNumericCode`; `HmacService` gains `signedValue` and
  `verifySignedValue`.** Breaking for a hand-written implementation, not for a consumer.

- **Client: the atom wrappers are public.** They moved from the unexported `client/internal/atoms.ts`
  to `client/Atoms.ts` and are exported as `AuthAtoms` from `effect-auth/client` — `rewrite`,
  `withPayload`, `withQuery`, `withoutPayload`, `layerFetch` and the `Keyed` / `PayloadRequest` /
  `QueryRequest` / `ReactivityKeys` shapes. `AuthClient.signIn`'s success is
  `AuthClient.SignInResult`, and every authenticated atom's error union gains `StepUpRequired`.

- **Testing: `AuthTest.Settings` gains `authenticators` and `signInPipeline`**, both provided
  underneath the deployment; `TestEmails` gains `smsKind` and the `sms({ to, code })` record
  builder, so a phone plugin's sender is one line into the existing outbox.

- **Migrations.** Core migration `0006_session_assurance` adds the three session columns; a consumer
  merging `Migrations.migrations` numbers their own above `0006`, and any hand-written
  `INSERT INTO sessions` must now state `authenticated_at`, which has no `DEFAULT`. Five plugin
  migration sets are added, each in a bookkeeping table of its own and none registered globally —
  compose each after `Migrations.layer`, because every one references `users`.

- **Service keys.** Four keys added in this wave stuttered the file name and were collapsed to the
  Amendment 17 scheme — `effect-auth/passkeys/WebAuthn`, `effect-auth/two-factor/TwoFactor`,
  `effect-auth/phone/Phone`, `effect-auth/one-tap/OneTap` — and `WebAuthnClient`'s was corrected to
  `effect-auth/client/internal/webauthn/WebAuthnClient`. `effect-auth/domain/SignIn/SignIn` and
  `effect-auth/domain/Challenges/Challenges` still stutter; see SPEC 19.15. Process-local context
  slots, so no wire format moved.

### Added

- **`Assurance`** (`effect-auth`): `Aal`, `AuthenticationFactor`, `AuthenticationMethod`,
  `AuthenticationMethods`, `AuthenticationMethodsJson`, `deriveAal`, `amrOf`, `AssurancePolicy`,
  `AssurancePolicyJson`, `policyToJson`, `CurrentAssurance`.
- **`SignIn`** (`effect-auth`): the one choke point every sign-in mints through — `SignIn`,
  `SignInService`, `CompleteOptions`, `SignInRequest`, `SignInDecision`, `SignInChallenge`,
  `SignInResult`, `proceed`, `SignInPipeline`, `SignInPipelineService`, `pipelineOf`, `combine`,
  `layerPipeline`, `appendPipeline`, `methodOf`, `signInOf`, `make`, `layerFor`, `layer`.
- **`Challenges`** (`effect-auth`): short codes over `Verifications` with no new table — handle-bound
  attempt budgets, peppered code hashes, and re-issue under the same handle with the original
  expiry. Requires `Hmac | Token | Verifications`.
- **`Authenticators`** (`effect-auth`): the seam every factor plugin contributes to — `list`,
  `revokeAll`, `combine`, `layer`, `append`.
- **`AuthCipher`** (`effect-auth`): HKDF-SHA-256 → AES-256-GCM under a named key class, AAD-bound,
  envelope `v1.<iv>.<ct>`. **`Totp`**: HOTP/TOTP with `generate`, `verify`, `stepAt`, `otpauthUri`.
  **`Plugin.withDefaults`**: the options-section resolver every plugin uses instead of a spread.
- **`Sessions`**: `Evidence`, `stampEvidence`, `elevate`, `ElevatedSession`, `recoveryCodeMethod`,
  `meetsAssurance`, `requireAssuranceFor`, `requireAssurance`.
- **`Passwords.reauthenticate(userId, password)`** and `passwordEvidence`; `SignInOptions` gains
  `current`.
- **`POST /auth/reauthenticate { password }` → `SessionWithUser`.** Appends a password entry,
  re-stamps `authenticatedAt`, rotates the token keeping the session id, and re-sets the cookie.
  `AuthClient.reauthenticate` and `AuthClient.withStepUp(effect, onStepUp)` go with it.
- **`RequireAssurance`** (endpoint annotation) and **`freshSession`** (the empty policy the library's
  own credential-changing endpoints carry), plus `MiddlewareLive.resolveAssurancePolicy`,
  `availableFactors` and `stepUpResponse`.
- **`AuthCookies.pluginCookie` / `pluginCookieFor`**, `OriginCheck.requireTrustedIfPresent` and the
  `OriginNotAllowed` (403) error, `RateLimits.consumeKeyed` (with its `always` option, which the
  two-factor lockout uses so that `rateLimit.enabled: false` does not switch it off) / `keyedKeyFor`, and
  `AuthHandlers.pendingCookieBaseName` / `pendingCookie` / `setPendingCookie` /
  `clearPendingCookie` / `mfaRequiredParam` / `withMfaRequired`.
- **`EmailOtp`** — the reference plugin. `POST /auth/email-otp/send`, `/verify` (200
  `SignedIn | Verified | PasswordReset`, or 202 `MfaRequired`), `GET /link?token=`, plus
  authenticated `step-up/{send,verify}` and `change-email/{send,verify}`. Owns no table. New cookie
  `__Host-effect_auth.email_otp_handle`, carrying `<purpose>.<handle>`.
- **`Username`** — `POST /auth/username/{sign-in,set,available}`, table
  `effect_auth_usernames` keyed on a PRECIS-cased form. `UsernameInvalid` (400), `UsernameTaken`
  (409). One password verification on every branch, whatever the name resolves to.
- **`Anonymous`** — `POST /auth/anonymous/{sign-in,delete}`, table `effect_auth_anonymous`. A real
  `users` row at `anon-<uuidv7>@anonymous.invalid` minted at `aal0`, so
  `Anonymous.identifiedPolicy` is the one guard that excludes every visitor. `layerHooks` installs
  the merge-on-sign-in hook; `sweep` is an `Effect` the deployment schedules. `NotAnonymous` (403).
- **`effect-auth/passkeys`** — seven endpoints under `/auth/passkeys`, tables
  `effect_auth_passkeys` and `effect_auth_passkey_users`, the `WebAuthn` seam with `layerSimple`
  over the new **optional peer dependency `@simplewebauthn/server@^13.0.0`**, `layerAuthenticators`,
  `PasskeysClient` and `PasskeysTest`. `PasskeyVerificationFailed` (401), `ChallengeExpired` (400),
  `CannotRemoveLastAuthenticator` (409), `WebAuthnUnavailable` (start-up).
- **`TwoFactor`** — nine endpoints under `/auth/two-factor` (TOTP, recovery codes, trusted devices),
  three tables, `layerSeams` underneath the deployment and `layer` over it, `TwoFactorClient` and
  `TwoFactorTest`. `TotpAlreadyEnrolled` / `TotpNotEnrolled` (409). New cookie
  `__Host-effect_auth.tdev`.
- **`Phone`** — seven endpoints under `/auth/phone`, table `effect_auth_phone_numbers`, the
  `SmsSender` seam, `E164` as a transform rather than a predicate, and five toll-fraud buckets.
  Ships refusing every number (`allowedCountries: []`) with both factor capabilities off.
- **`OneTap`** — `GET /auth/one-tap/nonce` and `POST /auth/one-tap/callback`, reusing the existing
  id-token verifier, the registered provider's own `userInfo` (including its `hd` rule) and
  `Accounts.linkOAuth`. Owns no table and stores no provider tokens. New cookie
  `__Host-effect_auth.onetap_nonce`.
- **Eight OAuth providers**: `Facebook` (Graph with `debug_token` binding, or Limited Login as
  OIDC), `Twitter` (Basic exchange, `confirmed_email`), `LinkedIn`, `Slack` (subject from the
  URI-namespaced claim, not `sub`), `Twitch` (explicit `claims` parameter), `Spotify`, `Notion`
  (`Notion-Version`, no refresh), `Linear` (GraphQL userinfo, `actor=user`). Plus
  `OAuthProvider.EmailVerifiedPolicy`, `applyEmailVerifiedPolicy`, `postJson` and `postForm`.
- **Clients**: `EmailOtpClient`, `UsernameClient`, `AnonymousClient`, `PasskeysClient`,
  `TwoFactorClient`, `PhoneClient`, `OneTapClient`. **Harnesses**: `EmailOtpTest`, `UsernameTest`,
  `AnonymousTest`, `PasskeysTest`, `TwoFactorTest`, `PhoneTest`, `OneTapTest`.

### Internal — no wire change

- `SessionCache` writes and reads its cookie through `Hmac.signedValue` / `verifySignedValue`. The
  envelope is byte-identical and `cacheCookieSeparator` is now `Hmac.signedValueSeparator`.
- `Passkeys` keeps the **high-water mark** of a credential's sign count when a regression is
  tolerated, so a cloned authenticator keeps announcing itself instead of going quiet after one
  event.
- The two-factor verify endpoints no longer clear the pending cookie on a refusal: its `Max-Age` is
  the challenge's own lifetime, and clearing it made a double-submitted typo cost the whole sign-in.


## Earlier in this cycle — the tightening and toolchain pass

Everything above is the Phase 1 wave. What follows predates it and is unreleased on the same tag.

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
