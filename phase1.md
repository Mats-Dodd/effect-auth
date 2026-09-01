# Phase 1 — Human authentication: scope

## Status

Scoping document, 2026-08-31. Nothing here is built. It is the synthesis of four research passes:
an audit of this repo's seams, a reading of better-auth's Phase-1 plugins and their fix history,
a survey of what `effect@4.0.0-rc.112` actually ships, and a standards brief (NIST 800-63B rev 4,
RFC 8176/6238/4226/9470/8265, WebAuthn L3, Ory/Clerk/Supabase/WorkOS session models). File and
line references below are to the tree at commit `ddf9904`.

`roadmap.md` §Phase 1 is the requirement. This document says what it costs and in what order.

## The verdict, in one paragraph

Phase 1 is **one breaking foundation wave followed by seven plugin modules that need zero further
core change.** Today the repo cannot express step-up at all — freshness is `createdAt + freshAge`
(`src/domain/Sessions.ts:168`, duplicated at `src/http/Middleware.ts:238`), so the only way to
re-authenticate is to mint a new session — and the four sign-in paths each mint sessions
privately, so a second-factor plugin has nowhere to interpose. Fixing both is a wire-visible change
to `Session` and to `signInEmail`'s success schema. Everything else the roadmap lists (email OTP,
username, anonymous, passkeys, TOTP, recovery codes, trusted devices, phone, One Tap, providers)
is buildable as a `src/<plugin>/` module on the §9 SDK once the foundation lands. **Ship the
foundation as `0.2.0`, break the wire exactly once, and never add an endpoint to `AuthApiGroup`
again in this phase** — that is simultaneously the roadmap's doctrine and the answer to the
breached tsc budget (SPEC §8.5), because plugin groups are not multiplied by the `F` parameter.

---

## Part A — Foundations (Wave 0, core, breaking)

### A1. `sessions` learns how it was authenticated

Migration `0006_session_assurance` (next core id; record at `src/sql/Migrations.ts:447`), model at
`src/domain/Schema.ts:172-195`:

| column | type | model | notes |
|---|---|---|---|
| `authenticated_at` | text NOT NULL, backfill `= created_at` | `DateTimeUtcFromString` | OIDC `auth_time`. Moves only on interactive authentication. **Never** on rolling refresh. |
| `aal` | text NOT NULL DEFAULT `'aal1'` | `Schema.Literals(["aal0","aal1","aal2"])` | Derived from `methods`, materialised so the cookie cache carries it and the compiler can exhaust it. |
| `methods` | text NOT NULL DEFAULT `'[]'` | `Schema.fromJsonString(Schema.Array(AuthenticationMethod))` | The honest, append-only log. Open set. Precedent: `accounts.scope` (`Schema.ts:255`). |

```ts
// src/domain/Assurance.ts (new)
const AuthenticationMethod = Schema.Struct({
  method: Schema.String,                       // "password" | "totp" | "passkey" | "emailOtp" | "oauth:google" | "recoveryCode" | "trustedDevice" | …
  completedAt: DateTimeUtcFromString,
  factor: Schema.Literals(["knowledge", "possession", "inherence", "none"]),
  phishingResistant: Schema.Boolean,
  restricted: Schema.Boolean,                  // NIST 800-63B §3.2.9 — SMS/PSTN
})
type Aal = "aal0" | "aal1" | "aal2"
```

Decisions folded in here, each of which one research pass argued for and another against:

- **Store `methods`, derive RFC 8176 `amr`.** There is no registered AMR value for email, magic
  link, federated login or anonymous (Supabase and Ory both invented private vocabularies). So the
  stored truth is our own `methods`; `Assurance.amrOf(methods)` is a pure function producing
  registered values only (`pwd`, `otp`, `sms`, `mca`, `swk`/`hwk` + `user` + `pop`, `mfa`) for the
  day a JWT plugin needs an `amr` claim. Two columns for one fact was rejected.
- **Trusted-device skips and recovery-code use are `methods` entries, not booleans.** A trusted
  device records `{ method: "trustedDevice", factor: "none" }` — it is a true statement about how
  the session was established and the derivation gives it zero weight. Same for `recoveryCode`
  (`factor: "possession"`), which policy can then refuse on the most sensitive endpoints. No
  `deviceTrusted` / `recoveryUsed` core columns.
- **No JSON `claims` blob.** Earlier design notes proposed one; `authenticatedAt` wants a real
  timestamp and `aal` wants a literal. The blob is used only where openness is real (`methods`).
- **`aal0` exists** so `requireAssurance({ aal: "aal1" })` is the one guard that excludes
  anonymous sessions instead of scattered `isAnonymous` checks.
- **`aal3` is not derived.** We do not verify attestation to a trust root, so `hardwareBound` from
  WebAuthn BE=0 would be an unverified claim. The type does not admit it.

The derivation, written once:

```
aal(methods):
  live = methods where factor != "none"
  if live is empty                                    -> "aal0"
  if any m in live where m.method is a UV=1 passkey   -> "aal2"   // multi-factor authenticator in one ceremony
  if |distinct m.factor in live| >= 2                 -> "aal2"   // pwd + totp, pwd + emailOtp, …
  else                                                -> "aal1"
```

Wire impact: all three are json-visible fields, so they appear on `GET /auth/session` and
`/auth/sessions`, and every pre-existing cookie-cache snapshot stops decoding (a miss, safe — the
exact precedent is `rememberMe` in SPEC §16.2).

### A2. Freshness is measured from `authenticatedAt`; sessions can be elevated

- `isFreshAt` (`Sessions.ts:168`) and the HTTP copy (`Middleware.ts:238-246`) become **one**
  function over `authenticatedAt`. The duplicate is the single most likely silent bug in this wave;
  collapse it.
- New `Sessions.elevate(sessionId, evidence: AuthenticationMethod)`: appends to `methods`,
  recomputes `aal`, re-stamps `authenticatedAt`, **rotates the opaque token** (id stays, so open
  tabs and the session list survive; a token captured at aal1 does not inherit aal2), returns the
  new token for the cookie re-set path `MiddlewareLive` already has, and publishes a new core event
  `SessionElevated`. Every endpoint that calls it is annotated `AuthoritativeSession`.
- Rolling refresh (`Sessions.verify`) must be audited to touch `expiresAt`/`updatedAt` only.
- `SessionNotFresh` is retired in favour of one error (A6). Since this wave already breaks the
  wire, batch it.

`freshAge` default stays **1 day**. Under the corrected semantics that is byte-identical to today
for a deployment with no step-up, so it is not a behaviour change. Whether it *should* tighten to
Ory's 15 min / GitHub's ~1 h is a product call (see Part D).

### A3. `SignIn.complete` — the choke point that does not exist yet

Four sites mint sessions privately, each with its own `beforeSessionCreate` read and `SignedIn`
publish: `Passwords.ts:701-728`, `Passwords.ts:762-779`, `oauth/Flow.ts:990-1005`,
`magic-link/MagicLink.ts:786-802`. AMR, AAL and the second-factor interrupt are properties of *the
sign-in*, and there is no single place to compute them. This is also, verbatim, the better-auth
failure: their 2FA gate is a literal three-path list (`two-factor/index.ts:431-437`), they
broadened it to every session-minting path and reverted four days later, and today a TOTP user who
signs in by magic link gets a full session with no second factor.

New `src/domain/SignIn.ts`:

```ts
interface CompleteOptions {
  readonly user: User
  readonly source: ProvisionSource                 // already exists (Hooks.ts:77)
  readonly evidence: ReadonlyArray<AuthenticationMethod>
  readonly current: Option<SessionWithUser>        // the request's existing session, if any
  readonly request: { rememberMe, ipAddress, userAgent }
}
type SignInDecision =
  | { _tag: "Proceed" }
  | { _tag: "Challenge"; kind: string; available: ReadonlyArray<string>; token: Redacted; expiresAt: DateTime.Utc }

interface SignInPipelineService {                   // Context.Reference, default {}
  readonly decide?: (o: CompleteOptions) => Effect<SignInDecision, PolicyRefused>
}
// combine / layer / append copied from Hooks.ts:252-255, 320-350, 374-409 — same monoid, same argument that it is not a registry
```

`SignIn.complete` runs `beforeSessionCreate` (its context gains `current`, additive), consults the
pipeline, and on `Proceed` mints the session with `methods = evidence`, `aal = derive(evidence)`,
`authenticatedAt = now`, publishing `SignedIn` (which gains `methods`, additive; `method` stays).
On `Challenge` it mints nothing.

**The pending second factor is not a session.** Both the internals audit and the standards brief
reached this independently, against the Ory/Supabase precedent, for a reason specific to this
codebase: a `sessions` row *is* a credential everywhere (`MiddlewareLive.ts:218-285`), and
`CurrentUser`/`CurrentSession` are being shaped as the principal for a future policy layer. A
half-authenticated session with `aal1` would be a working credential for every endpoint that
forgot to check — the fail-open shape of `AuthoritativeSession` with a total-2FA-bypass blast
radius. So the pending state is a `Verifications` row: `purpose("pending-auth", { evidence,
rememberMe, callbackURL })`, subject = userId, TTL 5–10 min, single-use, and browser-bound through
a `__Host-effect_auth.pending` cookie exactly as OAuth state already is (SPEC §16.1). The token
travels only in that cookie.

**How the client learns:** not as an error. Sign-in's success becomes a union —

```ts
type SignInResult =
  | SessionWithUser                                                        // 200, unchanged
  | { _tag: "MfaRequired"; available: ReadonlyArray<string>; expiresAt }   // 202
```

— with the second member on **202** so a deployment without factor plugins is byte-identical on
the wire today. (Verify that v4 `HttpApiEndpoint` accepts a multi-status success union via
per-member `HttpApiSchema.status`; if not, the fallback is a single 200 union body.) `MfaRequired`
carries no user id, no email, no secrets. Step-up on an *existing* session stays in the error
channel (A6), because there the caller asked for something else and was refused.

Both entry points — "complete a pending sign-in" and "elevate this session" — converge on one
verification path by discriminating the challenge subject:

```ts
type ChallengeSubject =
  | { _tag: "PendingAuth"; token }       // -> SignIn.complete with accumulated evidence
  | { _tag: "Session"; sessionId }       // -> Sessions.elevate
```

### A4. `Authenticators` — the seam that closes a live hole

Two core paths enumerate a user's sign-in methods and count **only `accounts` rows**:
`Accounts.unlink` (`Accounts.ts:510-529`, `CannotUnlinkLastAccount`) and `MagicLink.reclaim`
(`MagicLink.ts:668-719`, the unproven-account takeover defence). The moment a passkey plugin ships,
`unlink` falsely refuses a passkey-only user and `reclaim` **silently fails open** — it deletes
every `accounts` row and leaves the pre-registrant's passkey and TOTP intact, keeping their way into
the account the defence just claimed to have secured. better-auth has the identical gap and no
unified query anywhere.

The standards brief proposed a core `authenticators` registry table. Rejected: a core table whose
rows are written by plugins is a shared table wearing a hat, and it is exactly the shape the
roadmap forbids. Instead, a `Context.Reference` monoid modelled byte-for-byte on `AuthHooks`:

```ts
// src/domain/Authenticators.ts (new)
interface AuthenticatorSummary {
  readonly type: string; readonly id: string; readonly name: string | null
  readonly verifiedAt: DateTime.Utc | null; readonly lastUsedAt: DateTime.Utc | null
  readonly signIn: boolean; readonly secondFactor: boolean; readonly restricted: boolean
}
interface AuthenticatorsService {
  readonly list?: (userId: UserId) => Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError>
  readonly revokeAll?: (userId: UserId) => Effect<number, PersistenceError>
}
```

`combine` concatenates `list` and sequences `revokeAll`; default `{}` contributes nothing.
`Accounts.unlink` becomes "would leave zero *authenticators* that can sign in";
`MagicLink.reclaim` calls `revokeAll` **inside its existing transaction, under the existing
user-row lock** — which is why a plugin-side sweep bolted on afterwards would not be equivalent.
`list` also feeds `StepUpRequired.current.available` (A6) and the rule that a restricted factor
(SMS) can never be a user's only second factor. Each plugin still owns its table and serves its own
management endpoints; a deployment wanting an aggregate view builds it from the seam.

### A5. `Challenges` — short codes over `Verifications`

`Verifications` (`src/domain/Verifications.ts`) already *is* the challenge primitive for
high-entropy tokens: typed purposes, `issue`/`claim`/`retire`, atomic `DELETE … RETURNING`
(`SqlStores.ts:804-813`). WebAuthn challenges and the pending-auth marker fit it unmodified. A
6-digit code does not, for two reasons: `issue` mints its own secret (`Verifications.ts:474`), and a
wrong guess costs nothing — the only throttle is a 3/10s IP bucket keyed on a forgeable header.

One core change plus one shared module, no new table, no new column:

- `IssueOptions.secret?: Redacted` (`Verifications.ts:363-372`). Non-breaking; the "43 random
  characters" guarantee in the module header moves onto the default path. Do **not** add
  `peek`/`fail`/`claimOrFail` to `VerificationStore` — it is the swappable seam and every operation
  added there is one every backend must reimplement atomically.
- `src/domain/Challenges.ts`: `issueCode({ purpose, subject, digits, ttl, attempts })` and
  `verifyCode({ purpose, handle, code })`. The row's secret is a high-entropy **handle** (returned to
  the caller, delivered in a `__Host-` cookie or response, never the code); its payload carries
  `codeHash = Hmac.sign(code ‖ identifier)` — **peppered with the deployment secret, never
  `Token.hashToken`**, because a bare SHA-256 over a 10⁶ space is brute-forced offline in
  microseconds — plus `attemptsLeft`. `verifyCode` claims the handle atomically, compares in
  constant time, and on a mismatch **re-issues the same handle** (this is what `secret?` is for)
  with `attemptsLeft − 1` and the original `expiresAt`; at zero it does not re-issue. A server
  fault *before* the comparison (store error, decode failure) re-issues with the budget
  **unchanged** — an attempt is spent only by a comparison that ran; a corrupt budget reads as
  exhausted. This is better-auth's `atomicVerifyOTP` shape (`email-otp/routes.ts:1304-1352`, the best pattern in their
  codebase) with the attempt budget bound to a handle the attacker does not hold, which also closes
  their "anyone who knows the victim's email can burn all three attempts" DoS.
- Issuing a new code for `(purpose, subject)` retires outstanding ones. Resend cooldown is a
  `RateLimiter` bucket keyed on the identifier (`RateLimits.keyFor` already namespaces on bucket
  name + path; `consume` takes any key). Defaults: 10-minute TTL (NIST §5.1.3 ceiling), 5 attempts,
  60 s resend, 6 digits for SMS, **8 for email** (copy-paste is the norm; two orders of magnitude
  for free). `Token.generateNumericCode(digits)` by rejection sampling over
  `Crypto.randomBytes` — from `Token.ts`, the one seam randomness enters, never `Random`, which is
  seedable.

### A6. `Assurance` — step-up as a first-class requirement

- `Assurance.deriveAal`, `Assurance.amrOf` (A1).
- One error, `StepUpRequired` (403), replacing `SessionNotFresh`, which becomes the
  `{ maxAge }`-only case:

```jsonc
{ "_tag": "StepUpRequired",
  "required": { "aal": "aal2", "maxAge": 300, "methods": ["passkey","totp"], "allowRecovery": false },
  "current":  { "aal": "aal1", "authenticatedAt": "…", "available": ["totp","recoveryCode"] } }
```

  `current.available` comes from `Authenticators.list` and is what lets a client degrade
  gracefully (Clerk's "second_factor drops to first_factor when the user has none") without
  server-side guessing. A bearer transport renders the same error as RFC 9470's
  `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="aal2",
  max_age=300` when the JWT plugin exists; nothing to do now beyond keeping the shape compatible.
  **Do not pre-issue a challenge in the error** — any guarded request would then trigger an SMS.
- `requireAssurance(policy)`: the `Effect` guard, generalising `requireFresh`, for handler-level use.
- `RequireAssurance: Context.Reference<AssurancePolicy | undefined>` endpoint annotation, read in
  `MiddlewareLive` the way `AuthoritativeSession` is (`MiddlewareLive.ts:240`). Caveat from the
  primitives survey: annotations are erased from endpoint types, so the error must be declared on
  the middleware and therefore appears on every `Authenticated` endpoint's union. Accept that; it
  is true anyway once step-up exists.
- `POST /auth/reauthenticate { password }` — the one core step-up method (password re-entry →
  `Sessions.elevate` with `{ method: "password", factor: "knowledge" }`). Runs the same dummy-hash
  discipline as `signIn`. Factor plugins add theirs.
- Config: `assurance: { stepUpWindow = 12h }` — the AAL2 reauthentication window (rev 3's SHALL;
  rev 4 relaxed to 24 h SHOULD, which is a federal floor, not a library default).

### A7. Signed cookies and plugin cookies, once

`Cookies.ts` exports three specific cookies; there is no generic helper, so the trusted-device
cookie and the pending-auth cookie would each re-derive the `__Host-` decision (`Cookies.ts:149`),
the `sameSite` capping rule (SPEC §16.1), the expiry-must-repeat-path-and-domain rule
(`MiddlewareLive.ts:129`), and the MAC. Extract what already exists twice:

- `Hmac.signedValue(context, bytes)` / `Hmac.verifySignedValue` lifted from `SessionCache.ts:142`
  (its `macContext` domain-separation pattern generalised).
- `AuthCookies.pluginCookie({ baseName, hostOnly, maxAge })` → `{ name, security, options,
  expiredOptions }` from `AuthConfigService`.

Note `HttpApiBuilder.securitySetCookie` defaults `secure: true`, takes `maxAge` as a
`Duration.Input`, and is the only way to set a cookie from a handler.

### A8. Crypto additions

All hand-rolled on WebCrypto; effect ships random bytes and digests and nothing else (no HMAC,
base32, CBOR, AES, constant-time compare, or signature verify — confirmed by grep of the installed
rc.112 sources).

- `src/crypto/Totp.ts` + `src/internal/base32.ts` (~120 + ~50 LOC): HOTP/TOTP on `subtle` HMAC —
  keyed per secret, so its own constructor, not the `Hmac` service — dynamic truncation, ±1 step,
  RFC 6238 Appendix B vectors as the test corpus. **Defaults SHA1 / 6 digits / 30 s and nothing
  else by default**: Google Authenticator silently ignores `algorithm`, `period` and (on Android)
  `digits`, so stronger parameters produce codes we reject. No dependency; `otpauth` is 3 kLOC with
  its own hash, `speakeasy` is unmaintained.
- `src/internal/providerTokenCipher.ts` generalised to `secretCipher(keyInfo, aadOf)` and
  **exported** as `AuthCipher` (HKDF-SHA256 from `AuthConfig.secret` → AES-256-GCM, distinct HKDF
  `info` per secret class, AAD binds ciphertext to its row). TOTP secrets need it; a plugin
  re-implementing AES-GCM is the wrong answer.
- `Token.generateNumericCode` (A5).

### A9. Events

- `SignedIn` gains `methods` (additive; `method: string` stays and already carries `"magic-link"`).
- New core member `SessionElevated { sessionId, userId, method }` — adding to the closed union
  breaks consumer exhaustive matches; batch it in 0.2.0.
- Everything else a factor plugin says (`FactorEnrolled`, `RecoveryCodesLow`,
  `TrustedDeviceRevoked`, `PasskeyCounterRegression`, `AnonymousConverted`) is a `PluginEvent`.

### A10. Exports plugins already need

`withPayload` / `withQuery` / `rewrite` from `effect-auth/client` (`src/client/index.ts` exports
only `AuthClient` and `MagicLinkClient` today), `withDefaults` (`src/internal/records.ts:83`),
`AuthCipher` (A8), `Passwords.verifyPassword` + `absentUserId` are already public and are what the
username plugin must reuse for its timing defence.

### A11. Pull a tsc lever first

SPEC §8.5: instantiations 723,591 against a 620k ceiling, types 128,273 against 130k. The SPEC's own
instruction is that the levers (class-wrapped default groups; hand-written interfaces in place of
the sanctioned `ReturnType`) are the first thing the next wave does. And the counters are not
comparable across TS 5.7 → TS 7 (753k vs 1.43M), so **rebaseline** on TS 7 before deciding. Every
Phase 1 endpoint lives in a non-generic plugin group and costs nothing against `F`; the two core
additions (`reauthenticate`, the sign-in success union) are the only pressure.

### A12. The 0.2.0 breaking-change ledger

1. `Session` json gains `authenticatedAt`, `aal`, `methods` (cookie-cache snapshots miss once).
2. `signInEmail` (and magic-link `exchange`, OAuth callback semantics) success becomes
   `SessionWithUser | MfaRequired(202)`; `PasswordsService.signIn` success type follows.
3. `SessionNotFresh` → `StepUpRequired` on `changePassword`, `unlinkAccount`, and any endpoint
   that used `requireFresh`.
4. `AuthEvent` gains `SessionElevated`; `SignedIn` gains `methods`.
5. `beforeSessionCreate` context gains `current` (additive).
6. `Verifications.IssueOptions.secret?` (additive).
7. `AuthCookies`/`Hmac` gain helpers (additive). `AuthConfigService` gains `assurance` (compile
   break for hand-built configs, as `trustedOriginSet` was).

---

## Part B — Features (Waves 1–3, plugin modules, zero core change after Part A)

Each module follows `src/magic-link/` exactly: `Api.ts` (group class, camelCase id, `/auth/<kebab>`
prefix), `Handlers.ts` via `AuthHandlers.forGroup`, `<Name>.ts` (service, `Options`/`defaults`/
`makeConfig`, `layer`), own `Migrations.make({ table: "effect_auth_<plugin>_migrations" })` from
`0001`, own mailer/sender `Context.Service` in `Requirements`, own client built against its own
`HttpApi`, own `testing/<Name>Test.ts` with `Layer.fresh` around its outbox
(`MagicLinkTest.ts:109-124` — the memoisation trap every plugin harness hits). Plugin DDL uses
bounded `varchar` for ids and hashes so the `db-expansion.md` MySQL port stays mechanical.

### B1. Email OTP — `src/email-otp/` (Wave 1, first consumer of `Challenges`)

- **Endpoints:** `POST /auth/email-otp/send { email, purpose }` (200 always; `email` bucket),
  `POST /auth/email-otp/verify { code }` (handle from cookie) → `SignInResult`, plus purposes
  `signIn`, `verifyEmail`, `resetPassword` (→ hands a reset continuation, does not sign in),
  `stepUp` (→ `Sessions.elevate`), `changeEmail`. `signIn` and `stepUp` are **distinct purposes**
  even though they look identical, so a code phished under "confirm your email" cannot elevate.
- **Ship the hybrid:** one issuance mints both a code and a link backed by the same row; consuming
  either retires both. Solves magic link's scanner-prefetch consumption and cross-device weakness
  in one move. Magic link becomes a thin sibling; consider folding it into this module later.
- **No table.** `Challenges` over `Verifications`.
- **Evidence:** `{ method: "emailOtp", factor: "possession", phishingResistant: false }` — same
  proof as magic link (mailbox control), so same AMR contribution; as a second factor after a
  password it reaches aal2.
- **Adopt from better-auth:** verify-possession-first-then-reveal (`d8327f1fe`); create-then-delete
  for unknown addresses so write cost matches; `revokeUnprovenAccountAccess` — already ours (§10.2);
  `disableSignUp` returns `InvalidCode`, never `UserNotFound`. **Avoid:** plaintext default storage,
  unsalted SHA-256, `allowedAttempts || 3`, attempts keyed on the identifier alone, one shared
  rate-limit knob for send and verify, `overrideDefaultEmailVerification` monkey-patching.
- **Tests:** attempt exhaustion under concurrency, cross-purpose replay refused, resend retires the
  prior code, moving-clock expiry, unknown-address indistinguishability, hybrid consume-either.
- **Size:** ~5 src files, ~50 tests.

### B2. Username sign-in — `src/username/` (Wave 1)

- **Table:** `effect_auth_usernames(username_key varchar PK, username varchar, user_id UNIQUE FK
  CASCADE)`. Two forms per PRECIS (RFC 8265): `username_key` = `UsernameCaseMapped` (**NFC** +
  case-fold — not NFKC, which the roadmap draft assumed); `username` = display form. Confusables
  (UTS #39 skeleton) as an opt-in soft signal, not a unique constraint.
- **Endpoints:** `POST /auth/username/sign-in { username, password }` → `SignInResult`;
  `POST /auth/username/set` (authenticated, `requireAssurance({ maxAge })`);
  `POST /auth/username/available` **opt-in** and rate-limited — a username is public by design, so
  the availability oracle is acceptable, but it must be a deliberate choice.
- **The one rule:** resolve `username_key → userId | absentUserId`, call
  `Passwords.verifyPassword` (`Passwords.ts:417`, one constant-cost verify on every path), then
  `SignIn.complete`. Never reimplement `signIn`'s lookup. better-auth's equalisation is incomplete
  on the "user exists, no credential account" branch; ours goes through one function so it cannot be.
- **Validity on the write path**, not the route (better-auth `6b44606b7`: sign-up validated, admin
  create and update not). Defaults: 3–30, `[a-z0-9_-]` with Unicode opt-in, a shipped reserved list
  (`admin`, `root`, `support`, `api`, `.well-known`, our own route segments). Unique violation is
  caught and mapped, not surfaced as a driver error.
- Contributes `{ type: "password" }` to nothing new — the credential is the existing
  `local:credential` account; the username is a lookup key, not an authenticator.
- **Size:** ~4 src files, ~30 tests.

### B3. Anonymous accounts — `src/anonymous/` (Wave 1)

- **Identity:** a real `users` row with a synthetic address `anon-<uuidv7>@anonymous.invalid`
  (`users.email` is NOT NULL + unique and `Email` requires an `@`; `.invalid` is RFC 2606 reserved,
  never deliverable). Making `email` nullable would break `findByEmail`, `normalizeEmail`,
  magic-link `settle`, and step 2 of the OAuth linking algorithm — not worth it. Marker table
  `effect_auth_anonymous(user_id PK FK CASCADE, created_at, last_seen_at)`; **never** an
  `is_anonymous` core column.
- **Endpoints:** `POST /auth/anonymous/sign-in` (no body; per-IP `RateLimiter` bucket — better-auth
  has none and each hit writes two rows); `POST /auth/anonymous/delete`.
- **Evidence:** `[]` → `aal0`.
- **Conversion is driven by the pipeline, not a path list.** better-auth's matcher forgot
  `/one-tap/callback` and `/passkey/verify-authentication` (`a2029ef7f`) and silently no-op'd. Ours:
  the plugin appends a `beforeSessionCreate` reading `current`; when the request carries an
  anonymous session for user A and a session is being minted for user B, it runs the consumer's
  `onConvert({ anonymous, target })` **inside the mint transaction** and deletes A. A throw aborts
  the mint — better-auth awaited the callback uncaught *after* setting the cookie, leaving a valid
  session with an error response and an orphaned user. Provision-source `Plugin` already exists
  (`Hooks.ts:77`), so `Users.provision` needs no change.
- **GC:** a `Migrations`-owned sweep for anonymous users idle > 30 days (Firebase's default),
  exposed as an `Effect` the deployment schedules. CAPTCHA is the roadmap's "later" item; this is
  the feature that will want it first.
- **Size:** ~4 src files, ~30 tests.

### B4. Passkeys / WebAuthn — `src/passkeys/` (Wave 2)

- **Dependency decision:** `@simplewebauthn/server` as an **optional peer dependency** (the
  `@effect/sql-pglite` precedent in `package.json`), behind an effect-auth-owned `WebAuthn`
  `Context.Service` with a captured test seam. Hand-rolling is ~550–900 LOC of security-critical
  parsing (bounds-checked CBOR, authData, COSE→JWK for ES256/RS256/EdDSA, DER→raw ECDSA, ceremony
  validation) plus a fixture corpus we cannot mint without hardware, and it inherits L3 churn. TOTP
  is 120 lines against a frozen 2011 spec with published vectors; WebAuthn is not. Exported from a
  subpath (`effect-auth/passkeys`) so the default install keeps its one runtime dep. Better-auth
  ships passkey as its only separate package for exactly this reason.
- **Table:** `effect_auth_passkeys(id PK, user_id FK CASCADE, credential_id varchar UNIQUE
  (globally — better-auth's is merely indexed), public_key text (COSE, base64url via
  `Schema.Uint8ArrayFromBase64Url` — no `Model` blob helper, all-text migrations), sign_count,
  transports, aaguid, backup_eligible (immutable), backed_up (mutable, updated every ceremony),
  uv_initialised, name, created_at, last_used_at)` plus a per-user random `webauthn_user_handle`
  column on the plugin's own `effect_auth_passkey_users(user_id PK, handle)` — the WebAuthn
  `user.id` must be opaque and ≤ 64 bytes, and a DB key is not opaque in the privacy sense.
- **Challenges:** `Verifications` rows as-is — 32 random bytes, 5-min TTL, payload
  `{ ceremony: "registration" | "authentication", rpId, origin, userVerification, userHandle? }`.
  The **ceremony tag is mandatory** (better-auth `baeaa00bc`: a registration challenge completed an
  authentication and vice versa). Handle in a `__Host-` cookie (A7) binds the ceremony to the
  browser; the row makes it single-use (`8907c7df9`). Discoverable/Conditional-UI sign-in needs a
  user-less challenge — the subject is any string, so this is free.
- **Endpoints:** `POST /auth/passkeys/register/options` and `/register/verify` (both
  `requireAssurance({ maxAge })` — adding a credential is a step-up operation; better-auth got this
  right for passkeys and wrong for 2FA enable), `POST /auth/passkeys/authenticate/options`
  (`allowCredentials` scoped to the session user if one exists, else empty → usernameless; unknown
  username answers plausible **deterministic dummy credential ids** from `Hmac(username)` per
  WebAuthn L3 §14.6.2), `/authenticate/verify` → `SignInResult` or elevate per `ChallengeSubject`,
  `GET /auth/passkeys`, `POST /auth/passkeys/rename`, `POST /auth/passkeys/delete` (ownership
  enforced in the service, not per route — `bd9bd58f8` IDOR).
- **Server verifies** (delegated to the dep, policy ours): type, challenge, origin (**required in
  config**; better-auth falls back to the request's `Origin` header, which makes the RP origin
  attacker-controlled), `rpIdHash`, UP, UV per policy, alg allowlist ES256/RS256/EdDSA, credential
  id unique on register, **`userHandle` equals the stored handle** on discoverable sign-in, and —
  the check better-auth lacks — when the challenge was minted for a session user, the credential
  must belong to that user, or "re-authenticate as *this* user" is unenforceable.
- **Sign count:** if both stored and returned are 0, skip (synced passkeys never count); on
  regression emit `PasskeyCounterRegression`, hard-fail opt-in.
- **Evidence:** `{ method: "passkey", factor: uv ? "inherence" : "possession", phishingResistant:
  true }` with a `userVerified` marker — **a UV=1 passkey lands at aal2 in one ceremony with no
  second prompt**; a UV=0 tap is single-factor. Derived from the actual UV bit, never from the
  requested `userVerification: "preferred"`. better-auth passes `requireUserVerification: false` and
  has no notion of this — it is the largest single thing our foundation adds over prior art.
- **Errors:** one `PasskeyVerificationFailed` for bad signature / unknown credential / origin /
  rpId mismatch; `ChallengeExpired` separately (not user-specific).
- **Client:** the first client with real logic — a composite mutation atom whose body does
  `options → navigator.credentials.{create,get} → verify` inside one Effect over a `WebAuthnClient`
  browser service (`Effect.tryPromise`; `@simplewebauthn/browser` optional). Conditional UI:
  `mediation: "conditional"` + `autocomplete="username webauthn"`.
- **Tests:** a test authenticator in `testing/` that mints real ES256 assertions with WebCrypto
  (the `MockProvider.IdTokenSigner` shape, `MockProvider.ts:448-476`) so the dep verifies real
  signatures; ceremony-tag confusion, cross-user credential, counter policy, dummy-credential
  determinism, discoverable flow, UV→aal2 derivation.
- **Size:** ~8 src files, ~60 tests. The largest module.

### B5. TOTP + recovery codes + trusted devices — `src/two-factor/` (Wave 2, one module)

Bundled because "never leave a user with 2FA and no recovery path" is an invariant, not a feature
order, and trusted devices are meaningless without a second factor to skip.

**TOTP**
- Table `effect_auth_totp(user_id PK FK CASCADE, secret_ciphertext text (AuthCipher, AAD =
  user_id), verified_at NULL, last_used_step bigint, created_at)`. `verified_at IS NULL` is
  **never accepted for authentication** (better-auth `e78a7b120`: enabling before proof locked
  users out of their own accounts; and their `skipVerificationOnEnable` still exists — do not
  inherit it).
- `POST /auth/two-factor/totp/enroll` (`requireAssurance({ maxAge })`) → `{ otpauthUri, secret }`
  with `Schema.Redacted(…, { disallowJsonEncode })` on anything that must not reach an unintended
  response; pending enrolments expire in 15 min and abandon regenerates.
  `POST /auth/two-factor/totp/confirm { code }` → active + recovery codes generated **at this
  moment**, shown once. `POST /auth/two-factor/totp/verify { code }` → complete pending auth or
  elevate. `POST /auth/two-factor/totp/disable` (`requireAssurance({ aal: "aal2", maxAge })`; revokes
  trusted devices).
- **Replay:** reject any step ≤ `last_used_step` by an atomic conditional `UPDATE … WHERE
  last_used_step < ?` (RFC 6238 §5.2; ≤, not =, or an observed code replays within the window).
- Attempt budget: per-challenge via `Challenges` semantics; per-account lockout across challenges
  (better-auth's second layer, 10 failures → 15 min, `3a035e968`/`3ea364d5f` — the per-challenge cap
  alone is defeated by starting a new sign-in) as a `RateLimiter` bucket keyed on `userId` with a
  guarded reset.
- Evidence `{ method: "totp", factor: "possession", phishingResistant: false }`.
- Appends to `SignInPipeline.decide`: if the user has an active TOTP (or passkey-as-second-factor)
  and the evidence is single-factor and no trusted device is presented → `Challenge`. This is
  where magic-link sign-in correctly fails AAL2 instead of bypassing it.

**Recovery codes**
- Table `effect_auth_recovery_codes(id PK, user_id FK CASCADE, code_hash varchar UNIQUE, used_at
  NULL, created_at)`, one row per code. **Keyed hash — `Hmac.sign(code)` — not a fast hash and not a
  slow KDF.** Arithmetic: 10 chars of base32 is 50 bits, ≈ 3 GPU-hours per code against a fast
  hash; a salted slow KDF cannot be indexed so one verify costs up to N KDFs, a DoS lever. The keyed
  hash is O(1), constant-time, and useless without the deployment secret — precisely what the
  reserved `Hmac` module was for. 10 codes × 12 Crockford-base32 chars (60 bits), grouped
  `ABCD-EFGH-JKMN`, case-folded on input.
- Consume by single-row atomic `UPDATE … WHERE used_at IS NULL RETURNING` (per-code single-use,
  audit trail, no CAS on a blob — better-auth stores one encrypted JSON blob compared with `===`
  and exposes `viewBackupCodes` plaintext for any user id; diverge entirely).
- `POST /auth/two-factor/recovery/verify { code }` → aal2 for this session **flagged**
  (`{ method: "recoveryCode", factor: "possession" }`), notification email, `RecoveryCodeUsed`;
  policy may set `allowRecovery: false`. Do not silently downgrade — that locks a legitimate user
  out of the page where they would fix their 2FA. `POST /auth/two-factor/recovery/regenerate`
  (`requireAssurance({ aal: "aal2", maxAge })`) invalidates the set. `RecoveryCodesLow` at ≤ 3.

**Trusted devices**
- Table `effect_auth_trusted_devices(id PK, user_id FK CASCADE, token_hash varchar UNIQUE (Hmac),
  created_at, expires_at (absolute 30 d — **not rolling**; a rolling window is a permanent bypass
  for an active attacker), last_used_at, user_agent, ip_address, label)`; cookie
  `__Host-effect_auth.tdev` via A7, HMAC-bound to `userId` (better-auth's good idea), identifier
  **rotated on each use**, absolute expiry preserved.
- Grants: suppresses the interactive second-factor prompt at sign-in and contributes
  `{ method: "trustedDevice", factor: "none" }` — the session is aal1. NIST does not recognise
  device trust as a factor and there is no AMR value for it; recording the skipped factor's value
  would corrupt every downstream derivation. Routine browsing works; anything guarded by
  `requireAssurance({ aal: "aal2" })` still costs a real factor. Config
  `trustedDeviceSatisfies: "none" | "aal2"` defaulting to `"none"`, documented as non-conformant
  when flipped.
- Revoke-all on: password change/reset, any factor enrol/remove, recovery-code use or regeneration,
  email change, `revokeAll`. `GET /auth/two-factor/devices`, `POST …/devices/revoke`,
  `POST …/devices/revoke-all` — better-auth's only clearing path is disabling 2FA entirely.
- Contributes `{ type: "totp", secondFactor: true }` and `{ type: "recoveryCodes" }` to
  `Authenticators`; trusted devices are **not** authenticators.
- **Size:** ~10 src files, ~80 tests (RFC vectors, replay ≤, enrol state machine, lockout
  concurrency, recovery single-use under concurrency, device rotation, revoke-on matrix).

### B6. Phone / SMS OTP — `src/phone/` (Wave 3)

- Table `effect_auth_phone_numbers(phone_e164 varchar PK, user_id FK CASCADE UNIQUE, verified_at,
  created_at)`. **Parse to E.164 at the boundary** (`+`, digits, ≤ 15, country code 1–3) with a
  small hand-rolled validator — `libphonenumber` is an optional richer normaliser, not a core dep.
  better-auth's is a predicate, not a transform, called in 2 of 6 handlers, so `+1 555-0100` and
  `+15550100` are two accounts.
- `SmsSender` `Context.Service` in `Requirements` (`send({ to, body: Redacted }) →
  Effect<void, SmsDeliveryError>`), the `MagicLinkEmails` shape by analogy; never widen
  `AuthEmailsService`. Provider calls use `HttpClient.retryTransient` + `Effect.timeout` via
  `transformResponse` (no `HttpClient.timeout` exists). `TestSms` is `TestEmails.record` with
  `kind: "sms"`, no second outbox.
- **Two capabilities, declared separately:** "verified phone contact" and "phone as a sign-in
  method". better-auth's `/phone-number/verify` is an unconditional passwordless sign-in you get for
  free by adding the plugin for a contact field.
- **Toll-fraud controls ship by default** — the most expensive Phase 1 failure mode is an invoice:
  rate limits per destination, per destination **prefix**, per IP, per subject; a country allowlist
  that **defaults to empty (deny)**, forcing a decision; a send/verify conversion `Metric` and a
  `PluginEvent` when it collapses. This is the roadmap's "security constraints improve DX" in its
  purest form.
- Purposes namespaced (`phone:verify`, `phone:signIn`, `phone:stepUp`, `phone:resetPassword`) —
  better-auth used the raw number as identifier, so a reset code redeemed as a verify code.
  Constant-time compare (theirs is `!==` on this path in the same repo whose email path is
  constant-time).
- Evidence `{ method: "sms", factor: "possession", restricted: true }` — never reduces AAL, but a
  restricted type can never be a user's only second factor (NIST §3.2.9), enforced through
  `Authenticators.list`.
- **Size:** ~6 src files, ~45 tests.

### B7. Google One Tap — `src/one-tap/` (Wave 3)

- **It is not a new authentication method.** The credential is a Google-issued ID token; the
  endpoint does CSRF/nonce checks and then calls the **existing** `IdToken` verifier (JWKS cache
  with refetch-on-unknown-kid, `iss` ∈ {`accounts.google.com`, `https://accounts.google.com`},
  `aud` = client id, fail-closed — `ad35eadd1` was a period when One Tap accepted tokens minted for
  any Google app) and the **existing** `Accounts.linkOAuth` (sub wins; implicit link only when
  provider-verified AND local-verified; `one-tap.test.ts:348`). If One Tap grows its own
  verification code, we have made a mistake. Same path serves Sign in with Apple JS later.
- `POST /auth/one-tap/callback { credential, nonce }` → `SignInResult`. **Nonce bound**: server
  mints it into a short `__Host-` cookie, client echoes it into `google.accounts.id.initialize`,
  verify requires the match — better-auth plumbs `nonce` through the client and never checks it, so
  credentials replay for an hour. Redirect (`ux_mode: "redirect"`) mode additionally checks
  `g_csrf_token` cookie == body. `hd` restriction read from the Google provider config
  (`816d7f925`).
- FedCM is mandatory for GSI since Aug 2025 (`use_fedcm_for_prompt` is ignored; iframes need
  `allow="identity-credentials-get"`; moment-notification APIs are gone). Client: load
  `gsi/client` once, `initialize` with `client_id` **last** so `additionalOptions` cannot clobber
  it, `preventSilentAccess()` on sign-out.
- **Size:** ~4 src files, ~20 tests.

### B8. Additional social providers — `src/oauth/providers/` (Wave 3)

Providers are values (`OAuthProviderConfig` is inert data, `Provider.ts:161`) with the `exchange`
override and `userInfo` seams from SPEC Amendment 15, so each is a pure addition. Top eight by
demand: **Facebook, Twitter/X, LinkedIn, Slack, Spotify, Twitch, Notion, Linear** (Kakao/Naver/LINE
collectively outrank most of these in KR/JP). Special handling from better-auth's 35:

| provider | what needs the seam |
|---|---|
| Facebook | Limited Login `id_token` path with `emailVerified` forced false; otherwise `debug_token` validation binding `app_id` and `profile.id` |
| Twitter/X | PKCE always, Basic on token *and* refresh, email needs a second `users/me` call; `.invalid` placeholder |
| LinkedIn / Slack | OIDC; Slack's subject is `profile["https://slack.com/user_id"]` |
| Twitch | needs an explicit `claims` param or email is absent from the ID token |
| Notion | `Notion-Version` header, no refresh |
| Linear | userinfo is a GraphQL POST |
| Kakao / Naver | nested profiles; Kakao verified = `is_email_valid && is_email_verified` |

Adopt two of their descriptor decisions: `emailVerified` policy as a **required** field
(`"derived" | "never"`) so a new provider cannot omit it into permissive linking — of 35 providers,
15 return `false` unconditionally and can therefore never implicitly link, which is correct; and
identity only ever from the subject-claim seam, never from a profile mapper (their `id?: never`).

**Size:** ~1 file + ~5 tests per provider.

---

## Part C — Invariants to encode, not review for

better-auth's fix history repeats eight bug classes. Each maps to something our types or seams
should make unrepresentable, and each becomes a line in the Phase 1 definition of done:

1. **Read-then-write on a single-use credential** → every consume goes through `Verifications.claim`
   / `Challenges.verifyCode` / a `… RETURNING` update; no `find` → check → `delete` anywhere.
2. **Existence checks that never read `expiresAt`** → expiry is inside the consume predicate.
3. **Enumeration by error ordering** → verify possession first; reveal after.
4. **A rule enforced at one entry point but not its siblings** → validity on the write path
   (`Users.provision`, `SignIn.complete`, `Sessions.elevate`), ownership in the service, never per
   route.
5. **Path allowlists as security matchers** → the pipeline, never a regex over paths.
6. **Comparison in the wrong domain** → one `compareInStorageDomain`; never expose "get the stored
   secret".
7. **Response-header accumulation** → a challenge never coexists with a session cookie in one
   response; the test helper reads `getSetCookie()`, never a `Map`.
8. **Guards that fail open** → `AuthoritativeSession` is default-false today and every step-up /
   enrolment / factor-management endpoint must carry it; a corrupt attempt counter reads as
   exhausted; unresolvable client IP falls into the shared bucket (already ours).

Two more from their history that our current shape does not yet cover:

9. **Cookieless CSRF on send endpoints** (`086ca91f5`): `OriginCheck` today applies only inside
   `Authenticated` on the cookie path (SPEC "Cross-cutting"). Email-OTP send, phone send, magic-link
   sign-in and anonymous sign-in are *unauthenticated* POSTs that cost money or create rows, and a
   cross-origin form POST reaches them with no cookie at all. Phase 1 needs an `OriginCheck` guard
   these handlers call explicitly: an `Origin`/`Referer` that is present must be trusted; a request
   with neither (server-to-server) passes. Wave 1 item, before the first send endpoint ships.
10. **Delivery latency as an oracle**: a mail or SMS send that is awaited only on the known-user
    branch is a timing oracle (better-auth's email-OTP send includes a full SMTP round-trip only
    for existing addresses). `deliverEmail`'s existing swallow-and-log discipline must be joined by
    "deliver off the request path" — fork the send under the request's scope so both branches
    answer in the same time — or the no-enumeration guarantee is prose.

Plus the standing ones: deterministic `Clock` (`DateTime.now`, never `Date`; `layerHttpMovingClock`
not `freshClock` for handlers), `Model.Sensitive` on every secret column named so the OpenAPI gate
(`tokenHash|passwordHash|valueHash`) can be extended to it, no sixth cast (plugin groups stay
non-generic — SPEC §10.3.2 — and answer the base user projection), `--maxWorkers=2`, per-plugin
migration tables from `0001`.

---

## Part D — Decisions needed before Wave 0

1. **Sign-in success union on 202 vs. a single 200 union body.** Recommend 202 (byte-identical
   wire for deployments without factors) if v4 `HttpApiEndpoint` supports it; needs a 30-minute spike.
2. **`freshAge` default.** Keep 1 day (no behaviour change) or tighten to 1 h now that it means
   "since last interactive authentication". Recommend keep, revisit when a consumer asks.
3. **`SessionNotFresh` → `StepUpRequired` rename.** Recommend yes, in this one breaking wave.
4. **`@simplewebauthn/server` as optional peer dep.** Recommend yes; the alternative is ~350 LOC
   of ES256-only, registration-`none`-only code that rejects Windows Hello RS256 credentials.
5. **Fold magic link into email-otp** (shared row, hybrid link+code) now or later. Recommend
   later — ship email-otp with the hybrid and deprecate magic link's separate module in Phase 2.
6. **tsc budget:** rebaseline on TS 7 and keep a ceiling, or drop the instantiation gate and keep
   only the check-time gate. Recommend rebaseline.
7. **Anonymous conversion semantics:** single path (callback + delete anonymous user, better-auth's
   model made transactional) vs. also "adopt in place" for the credential-sign-up case. Recommend
   single path for the first cut.
8. **Freeze the `Aal` strings as wire format now?** A Phase 3 JWT plugin would emit them as `acr`
   (Ory's `aal1`/`aal2` convention, not ISO 29115 integers). Recommend yes — they already appear on
   `GET /auth/session` after A1, so they are wire format whether or not we say so.

---

## Part E — Execution

| wave | modules | core? | rough size | workflow shape |
|---|---|---|---|---|
| 0 | Foundations A1–A12, SPEC amendment, README | yes, breaking → `0.2.0` | ~6 new files, ~14 touched, ~120 tests | 5–6 Opus builders on disjoint sets (schema+migration+Sessions / SignIn+pipeline+4 call sites / Authenticators+unlink+reclaim / Challenges+Verifications+Token / Assurance+Middleware+reauthenticate / Cookies+Hmac+Cipher+exports), 2 Fable reviewers, 1 fixer, 1 Fable gate on the breaking ledger |
| 1 | Email OTP, Username, Anonymous | no | ~13 files, ~110 tests | 3 Opus builders (one per module, disjoint), 2 Fable reviewers (one adversarial on enumeration/timing), 1 fixer |
| 2 | Passkeys; Two-factor (TOTP + recovery + trusted devices) | no (optional peer dep added) | ~18 files, ~140 tests | 4 Opus builders (passkeys server / passkeys client+test authenticator / totp+recovery / trusted devices+pipeline decider), 2 Fable reviewers, 1 fixer, 1 Fable gate on the AAL matrix |
| 3 | Phone, One Tap, ~8 providers | no | ~14 files, ~100 tests | 3 Opus builders + 1 for providers, 2 Fable reviewers, 1 fixer |

Wave 0 must be reviewed against one question above all others: **can any request obtain
`CurrentSession` at an assurance it did not earn?** — through a pending-auth token, a trusted-device
cookie, a cookie-cache snapshot written before elevation, a rolling refresh moving
`authenticatedAt`, or a magic-link/OAuth path that never consulted the pipeline. Everything in
Waves 1–3 rests on that answer being no.

Builders should read better-auth's security suites before writing ours — they encode invariants
the source never states: `plugins/two-factor/two-factor.security.test.ts`,
`two-factor.account-lockout.test.ts`, `two-factor.attempt-cap.test.ts`,
`email-otp.test.ts:2100-2283` (atomic consume), `anon.test.ts:255-289` (`anonymousUserId`
injection), `username.test.ts:60-100` (decoy credential account), `one-tap.test.ts:348` (sub wins
over email). Semantics only, never code.

Research inputs (ephemeral, session scratchpad): `report-auth-internals.md`,
`report-better-auth.md`, `report-effect-primitives.md`, `report-standards.md`.
