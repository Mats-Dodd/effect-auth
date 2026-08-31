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
export class Sessions extends Context.Service<Sessions, SessionsService>()("effect-auth/Sessions") {}
```

Rules:
- Interface name = `<ClassName>Service` (e.g. `SessionsService`, `PasswordHasherService`,
  `UserStoreService`). Where an equivalent inline/anonymous shape exists today, extract it —
  service keys and runtime behavior must not change.
- `make` returns the interface type explicitly.
- Applies to: Sessions, Accounts, Passwords, AuthEvents, the four stores, WithAuthTransaction,
  PasswordHasher, Hmac, Token, AuthConfig, AuthEmails, OAuthProviders, OAuthFlow, and any other
  `Context.Service` in src/. (Stores.ts may already be close — normalize the naming.)
- Purely mechanical and non-breaking: exported class names, service key strings, and member
  signatures are unchanged.

## 5. The permitted boundary casts (and only these)

1. `src/http/Handlers.ts` — `HttpApiBuilder.group` needs the concrete api type; a library
   accepts any consumer api structurally containing the auth group. Tighten the constraint from
   `HttpApiGroup.Constraint` to the auth group's actual type
   (`{ readonly groups: { readonly auth: typeof AuthApiGroup } }` or the tightest shape that
   accepts `HttpApi.make("app").addHttpApi(AuthApi).add(other)`), keep ONE `as` with a
   why-this-is-safe comment.
2. `src/client/AuthClient.ts:466` — same boundary for `AtomHttpApi.Service`. Same treatment.
   Also replace the `AtomResultFn<any, A, E>` helper params with proper generics.
3. `src/domain/Schema.ts` — `makeUserModel`. `VariantSchema`'s field validation and variant
   extraction cannot be proved for a field map that is still a type parameter, so the model is
   built and type-checked once against the *erased* field map (`buildUserModel`) and re-typed on
   the way out. `UserModel<F>` is the statement of what that value is, and every consumer in the
   library is checked against the statement rather than against the construction. Added by the
   custom-user-fields wave; keep it to exactly one `as unknown as` in that module.
4. `src/client/AuthClient.ts` — the `signUpEmail` mutation atom's *argument* type. `signUpEmail`
   is the one endpoint whose payload type mentions `F`, and `HttpApiEndpoint.ClientRequest`
   branches on the payload type to decide the request shape; a conditional over an `F` that is
   still a type parameter stays deferred, so inside the generic `make` the argument type has no
   writable form at all. At a call site, where `F` is a concrete field map, it resolves to exactly
   what the cast states. Only the argument is named — the atom, the request it issues and the
   schema it encodes through are `AtomHttpApi`'s own. Added by the custom-user-fields wave; keep
   it to exactly two `as unknown as` in that module.

   The same deferral is why `src/http/Handlers.ts` narrows to the *base* group rather than to
   `AuthApiGroupOf<F>`: a handler built against a parameterized payload could not read
   `payload.name`. It is a widening in both directions that the module honours — the extras of a
   payload are recovered through `model.extrasOf`, and the extras of a response are produced by
   `model.toPublic` — and it keeps the nineteen handlers type-checked once rather than once per
   deployment. Cast count there is unchanged.

## 6. Definition of done (gates — the final reviewer runs all of these)

1. `pnpm build && pnpm check && pnpm test` green (357+ tests; count must not go down).
2. Grep gate over `src/` (tests excluded):
   `grep -rnE "as any|as unknown|: any\b|<any[,>]| as Layer| as Effect|@ts-expect-error|@ts-ignore" src/`
   returns EXACTLY the two §5 casts (plus type-level `any` only where effect's own APIs force a
   variance position — each such site needs a one-line comment naming the forcing API, and the
   final reviewer must agree it's forced).
3. No conditional types in any exported layer/function signature.
4. Every `Context.Service` in src/ follows §4.
5. README quickstart, example app (`examples/basic`), `testing/TestLayer.ts`, and the client all
   compile against the new API; README shows both `Auth.layer` and `Auth.layerWithOAuth`.
6. SPEC.md gains an "Amendments" entry (append to the existing section) recording: providers as
   values, the two entry points, the narrowed Services, the interface-split convention.
7. All conventions from SPEC.md §"Coding conventions" still hold (it.effect, assert, JSDoc
   categories, etc.).
