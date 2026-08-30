/**
 * Type-level tests for the API constraint of `AuthHandlers.layer`.
 *
 * The parameter is generic because `HttpApi` is invariant in its group union: a
 * library cannot name the composed API a consumer will build. But "generic" is
 * not "anything" — the intersection pins `groups.auth` to `effect-auth`'s own
 * group, so an API that happens to carry *some* group called `auth` no longer
 * slips past the one boundary cast in `src/http/Handlers.ts`.
 *
 * There is nothing to run: `tsc` is the test. It lives outside `*.test.ts` on
 * purpose so vitest does not collect an empty suite.
 */
import type { Layer } from "effect"
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { AuthApi } from "../../src/http/AuthApi.js"
import type { HandlerServices } from "../../src/http/Handlers.js"
import * as AuthHandlers from "../../src/http/Handlers.js"

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
const eq = <T extends true>(_: T): void => {}

// ---------------------------------------------------------------------------
// Accepted: the auth API on its own, and a composed one.
// ---------------------------------------------------------------------------

const Todos = HttpApiGroup.make("todos").add(
  HttpApiEndpoint.get("listTodos", "/todos", { success: Schema.Array(Schema.String) })
)

const ComposedApi = HttpApi.make("app").addHttpApi(AuthApi).add(Todos)

const composed = AuthHandlers.layer(ComposedApi)
const standalone = AuthHandlers.layer(AuthApi)

// The identifier of the service produced follows the *consuming* API, and the
// requirements stay exactly `HandlerServices` — no group of the consumer's own
// leaks into either channel.
eq<
  Exact<
    typeof composed,
    Layer.Layer<HttpApiGroup.Service<"app", "auth">, never, HandlerServices>
  >
>(true)
eq<
  Exact<
    typeof standalone,
    Layer.Layer<HttpApiGroup.Service<"effect-auth", "auth">, never, HandlerServices>
  >
>(true)

// ---------------------------------------------------------------------------
// Rejected: the loose shapes the old `HttpApiGroup.Constraint` constraint let
// through. Each `@ts-expect-error` below is the test — remove the tightening
// from `AuthHandlers.layer` and these lines stop erroring, which fails `tsc`.
// ---------------------------------------------------------------------------

/** Somebody else's group, sharing only the name. */
const Impostor = HttpApiGroup.make("auth").add(
  HttpApiEndpoint.get("ping", "/ping", { success: Schema.String })
)
const ImpostorApi = HttpApi.make("app").add(Impostor)

// @ts-expect-error — `groups.auth` is not `typeof AuthApiGroup`; the handlers
// would have been built against endpoints this API does not declare.
AuthHandlers.layer(ImpostorApi)

/** The auth group, but re-prefixed after the fact — its endpoint paths differ. */
const PrefixedApi = HttpApi.make("app").addHttpApi(AuthApi).prefix("/api")

// @ts-expect-error — a prefixed group is a different group type, and the routes
// registered would not be the ones this API serves.
AuthHandlers.layer(PrefixedApi)

/** No auth group at all. */
const TodosApi = HttpApi.make("app").add(Todos)

// @ts-expect-error — there is no `auth` group to implement.
AuthHandlers.layer(TodosApi)
