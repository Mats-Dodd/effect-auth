# effect-auth tightening refactor — ground truth

Companion to SPEC.md (which stays authoritative for behavior/security). This refactor changes
API shape and internal style only — **zero behavior changes**, all 357 existing tests keep their
semantics (update call sites, not assertions, except where the API change forces it).

## Goals

1. **No type gymnastics.** No value-dependent layer types, no conditional types in layer
   signatures, no `Layer.Layer<any, any, any>`, no `as` casts — except the two documented
   boundary casts (see §5). Enforced by the grep gate in §6.
2. **Idiomatic Effect layer composition.** Optionality via composition (consumer adds a layer),
   never via an options field that mutates a conditional type. Linear `pipe` chains, no named
   intermediate layer tiers.
3. **Interface-split convention** for every service (§4).

## 1. Providers become values (kills Provider.ts gymnastics)

`OAuthProviderConfig` is inert data — it must not be wrapped in Layers.

- `Github.make(options): OAuthProviderConfig` and `Google.make(options): OAuthProviderConfig`
  (pure constructors; currently these exist internally — promote them to the public API).
- `Github.makeConfig(options): Effect<OAuthProviderConfig, ConfigError>` replaces
  `Github.layerConfig` (per-field `Config` values, same fields as today). Same for Google.
- DELETE: `Provider.layerMerge`, `Provider.layerEmpty`, the per-provider `layer`/`layerConfig`
  exports, the `Layer.build` loop, and the cast at Provider.ts:358.
- KEEP: `OAuthProviders` service + `makeRegistry(providers)`; add
  `OAuthProviders.layer(providers: ReadonlyArray<OAuthProviderConfig>): Layer<OAuthProviders>`
  = `Layer.succeed(OAuthProviders)(makeRegistry(providers))`.
- Registry semantics unchanged (later ids override earlier; null-prototype record).

## 2. Two static entry points (kills Auth.ts gymnastics)

Replace the single shape-shifting `Auth.layer` with:

```ts
Auth.layer(options)          // no OAuth. No `providers` field. Exact type: no HttpClient, no OAuthFlow.
Auth.layerWithOAuth(options) // options.providers: readonly [OAuthProviderConfig, ...OAuthProviderConfig[]]
                             // (non-empty). Exact type: + OAuthFlow in Services, + HttpClient in Requirements.
```

- DELETE from Auth.ts: `ProviderLayers`, the `Providers` generic on `Options`/`Extras`/
  `Services`/`Requirements`, both conditional types, the runtime `providers.length` branches,
  the `Layer.Layer<any, any, any>` intermediate, and the final `as Layer.Layer<...>` cast.
  `compose` must typecheck with NO casts — if it doesn't, the design is wrong, fix the design.
- `layerConfig` / `layerConfigWithOAuth` mirror the same split (`makeConfig` effects compose in
  the `Layer.unwrap`).
- Composition style: one linear `pipe` per entry point, e.g.

```ts
middlewareLayer.pipe(
  Layer.provideMerge(passwordsLayer),
  Layer.provideMerge(Layer.mergeAll(sessionsLayer, accountsLayer)),
  Layer.provide(hmacLayer),
  Layer.provideMerge(Layer.mergeAll(SqlStores.layer, eventsLayer(...), RateLimits.layer, configLayer, ...)),
  Layer.provide(Layer.mergeAll(tokenLayer, hasherLayer, AuthCookies.layerRedactedHeaders(...)))
)
```

  (`layerWithOAuth` inserts `Layer.provideMerge(flowLayer)` + `Layer.provide(OAuthProviders.layer(providers))`
  at the right tier. Exact tiering: whatever discharges dependencies with `provide` vs
  `provideMerge` chosen by §3 — derive it, don't copy this sketch blindly.)

## 3. Narrowed `Services` (kills the 13-service union)

Exposed (provideMerge): `AuthConfig`, `AuthEvents`, `Sessions`, `Accounts`, `Passwords`,
`Authenticated`, `RateLimiter.RateLimiter`, the four stores (`UserStore`, `SessionStore`,
`AccountStore`, `VerificationStore`) — i.e. everything `AuthHandlers`' `HandlerServices` lists
plus events/stores. `layerWithOAuth` adds `OAuthFlow`.

Internal (provide, NOT exposed): `Token`, `Hmac`, `PasswordHasher`, `OAuthProviders`.
Verify against the real `HandlerServices` in src/http/Handlers.ts before finalizing the list;
`AuthHandlers.layer` provided with `Auth.layer*` must discharge completely. Update
`testing/TestLayer.ts` accordingly (it may expose more for tests — that's fine, it's the test layer).

## 4. Interface-split convention (every service, whole codebase)

For each `Context.Service`, a named, exported, JSDoc'd interface holds the definition; the class
is only the key:

```ts
/** The Sessions service definition. @category models @since 1.0.0 */
export interface SessionsService {
  readonly create: (input: CreateSession) => Effect.Effect<CreatedSession, PersistenceError>
  // ...
}

/** @category services @since 1.0.0 */
export class Sessions extends Context.Service<Sessions, SessionsService>()("effect-auth/domain/Sessions") {}
```

Rules:
- Interface name = `<ClassName>Service` (e.g. `SessionsService`, `PasswordHasherService`,
  `UserStoreService`). Where an equivalent inline/anonymous shape exists today, extract it —
  service keys and runtime behavior must not change *in this wave*. (The keys were later
  module-qualified as their own deliberate step: `"effect-auth/Sessions"` →
  `"effect-auth/domain/Sessions"`, SPEC.md Amendment 17. The example above is already in the
  current form.)
- `make` returns the interface type explicitly.
- Applies to: Sessions, Accounts, Passwords, AuthEvents, the four stores, WithAuthTransaction,
  PasswordHasher, Hmac, Token, AuthConfig, AuthEmails, OAuthProviders, OAuthFlow, and any other
  `Context.Service` in src/. (Stores.ts may already be close — normalize the naming.)
- Purely mechanical and non-breaking: exported class names, service key strings, and member
  signatures are unchanged.

## 5. The permitted boundary casts (and only these)

As of the v2 wave (plugin SDK, core parity, cookie cache, custom user fields) the gate

```sh
grep -rnE "as any|as unknown" src/
```

returns exactly these five lines, and no others:

| # | Site | What is restated |
|---|---|---|
| 5.1 | `src/http/Handlers.ts:397` | `HttpApiBuilder.group`, for one named group of a composed API |
| 5.3 | `src/domain/Schema.ts:1161` | `makeUserModel`, re-typing the erased model build |
| 5.2 | `src/client/AuthClient.ts:621` | `AtomHttpApi.Service`, the same boundary as 5.1 |
| 5.4 | `src/client/AuthClient.ts:643` | the argument type of the `signUpEmail` mutation atom |
| 5.4 | `src/client/AuthClient.ts:655` | the argument type of the `updateUser` mutation atom |

Line numbers move; the count and the modules do not. Three casts is the ceiling for
`AuthClient.ts`, one for `Handlers.ts`, one for `Schema.ts`, and zero everywhere else in `src/`.
Each is justified in-code at its own site, at the length the four entries below give it.

**This gate is no longer prose.** `typescript/no-unsafe-type-assertion` runs at error over the whole
tree, so a sixth cast does not need a reviewer to notice it — `pnpm check` refuses it. The five
above are the five `// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- REFACTOR.md
§5 boundary cast` suppressions in `src/`, and adding one is a visible, greppable, reviewable act
rather than a line that reads like any other. The grep above still works and is still the fastest
way to see the list; it is now a cross-check on the linter rather than the only enforcement. The
rule has one further suppression outside `src/`, in `test/http-api/Middleware.test.ts`, where
`HttpApiMiddleware.isSecurity` can only be reached through a cast past an upstream typing gap; the
`src/` ceiling of five is unchanged. Amending this section means editing both the table and the
suppression in the file.

1. `src/http/Handlers.ts` — `HttpApiBuilder.group`, restated for one named group of a composed
   API (`buildGroup`). Two things about its signature make it unusable from a library: `HttpApi`
   is invariant in its group union, so a consumer's composed api is not assignable to
   `HttpApi<ApiId, typeof AuthApiGroup>`; and its group identifier is constrained by
   `HttpApiGroup.Identifier<Groups>`, a conditional that stays deferred while `Groups` is a type
   parameter, so no generic caller can name the group it implements whatever it casts the api to.
   What is cast is therefore the *function*, not the api, and the function being cast is a
   two-line wrapper that reads the identifier off the group value and passes the api through
   untouched. Both callers — `forGroup` (the plugin door) and `layer` — pin `groups[id]` to the
   group they were given at every call site, which is the check the types can no longer make.
   Keep it to exactly one `as unknown as` in that module. Widened by the plugin-SDK wave, which
   added `forGroup`.
2. `src/client/AuthClient.ts` — same boundary for `AtomHttpApi.Service`. Same treatment.
   Also replace the `AtomResultFn<any, A, E>` helper params with proper generics.
3. `src/domain/Schema.ts` — `makeUserModel`. `VariantSchema`'s field validation and variant
   extraction cannot be proved for a field map that is still a type parameter, so the model is
   built and type-checked once against the *erased* field map (`buildUserModel`) and re-typed on
   the way out. `UserModel<F>` is the statement of what that value is, and every consumer in the
   library is checked against the statement rather than against the construction. Added by the
   custom-user-fields wave; keep it to exactly one `as unknown as` in that module.
4. `src/client/AuthClient.ts` — the *argument* type of the mutation atoms whose payload mentions
   `F`: `signUpEmail`, and `updateUser` since the core-parity wave. `HttpApiEndpoint.ClientRequest`
   branches on the payload type to decide the request shape; a conditional over an `F` that is
   still a type parameter stays deferred, so inside the generic `make` the argument type has no
   writable form at all. At a call site, where `F` is a concrete field map, it resolves to exactly
   what the cast states. Only the argument is named — the atom, the request it issues and the
   schema it encodes through are `AtomHttpApi`'s own. Added by the custom-user-fields wave, widened
   by core parity; keep it to exactly one such cast per parameterized-payload endpoint, and
   therefore to three `as unknown as` in that module in total (this pair plus §5.2's).

   The same deferral is why `src/http/Handlers.ts` narrows to the *base* group rather than to
   `AuthApiGroupOf<F>`: a handler built against a parameterized payload could not read
   `payload.name`. It is a widening in both directions that the module honours — the extras of a
   payload are recovered through `model.extrasOf`, and the extras of a response are produced by
   `model.toPublic` — and it keeps the twenty-eight handlers type-checked once rather than once per
   deployment. Cast count there is unchanged.

## 6. Definition of done (gates — the final reviewer runs all of these)

1. `pnpm build && pnpm check && pnpm test` green (count must not go down; 357 at the end of the
   tightening refactor, 643 at the end of the v2 wave, 743 after the lint calibration).
   `pnpm check` at zero lines of output — a warn-level finding is a finding.
2. Grep gate over `src/` (tests excluded):
   `grep -rnE "as any|as unknown|: any\b|<any[,>]| as Layer| as Effect|@ts-expect-error|@ts-ignore" src/`
   returns EXACTLY the five §5 casts and nothing else — no `any` in a type position anywhere in
   `src/`, forced or otherwise. (If effect's own APIs ever force one, it needs a one-line comment
   naming the forcing API and the final reviewer has to agree it is forced. None does today.)
   Since the lint calibration this is belt-and-braces: `typescript/no-unsafe-type-assertion` at
   error is what actually holds the line, and the reviewable artefact is the suppression list —
   `grep -rn "oxlint-disable" src test`, which must return the five §5 casts, the two
   `effecttsgo/global-date` epoch constants in `src/http/Cookies.ts`, the one
   `effecttsgo/catch-conditional-refail-to-catch-if` in `src/http/Handlers.ts`, and the one
   `typescript/no-unsafe-type-assertion` in `test/http-api/Middleware.test.ts`. Every suppression is
   a single `oxlint-disable-next-line` with its reason — inline after `--`, or, where the reason
   needs a paragraph, in the comment block directly above it. No blanket or file-level disables.
3. No conditional types in any exported layer/function signature, and exactly one `ReturnType` in an
   exported signature (`AuthApiGroupOf`, sanctioned in SPEC.md §8.4). `grep -rn ReturnType src/`
   returns a second hit, `Effect.Services<ReturnType<typeof respond>>` in
   `src/testing/TestHttpClient.ts`: a local, non-exported type that predates this wave, and not a
   signature violation. The gate is over exported signatures, not over the grep.
4. Every `Context.Service` in src/ follows §4.
5. README quickstart, example app (`examples/basic`), `testing/TestLayer.ts`, and the client all
   compile against the new API; README shows both `Auth.layer` and `Auth.layerWithOAuth`.
6. SPEC.md gains an "Amendments" entry (append to the existing section) recording: providers as
   values, the two entry points, the narrowed Services, the interface-split convention. The v2 wave
   adds §§8–12 for the typed-view kernel, the plugin SDK, magic link, core parity and the cookie
   cache.
7. All conventions from SPEC.md §"Coding conventions" still hold (it.effect, assert, JSDoc
   categories, etc.).
8. The generated OpenAPI document (`test/http-api/__snapshots__/openapi.json`) mentions no
   `tokenHash`, `passwordHash` or `valueHash`, in any casing.
