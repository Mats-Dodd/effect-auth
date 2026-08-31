/**
 * Type-level tests for the magic link plugin's public surface.
 *
 * Two claims are being made, and neither can be tested at run time. The
 * handlers' API parameter pins `groups.magicLink` to *this* group — an API that
 * merely carries a group under that name is rejected rather than mis-served. And
 * a plugin's layer signature stays plain: no group of the consumer's own, and no
 * user-field parameter, leaks into either channel.
 *
 * There is nothing to run: `tsc` is the test. It lives outside `*.test.ts` on
 * purpose so vitest does not collect an empty suite.
 */
import type { Layer } from "effect"
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import type { Atom } from "effect/unstable/reactivity"
import type { InvalidToken, RateLimited } from "../../src/domain/Errors.js"
import type { SessionWithUser } from "../../src/domain/Schema.js"
import type { Ok } from "../../src/http/AuthApi.js"
import { AuthApi } from "../../src/http/AuthApi.js"
import type { SignUpDisabled } from "../../src/magic-link/Api.js"
import { MagicLinkApi, MagicLinkApiGroup } from "../../src/magic-link/Api.js"
import type { HandlerServices } from "../../src/magic-link/Handlers.js"
import { handlers } from "../../src/magic-link/Handlers.js"
import type { MagicLink, Options, Requirements } from "../../src/magic-link/MagicLink.js"
import { layer } from "../../src/magic-link/MagicLink.js"
import { MagicLinkClient } from "../../src/client/index.js"

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
const eq = <T extends true>(_: T): void => {}

// ---------------------------------------------------------------------------
// The layer: plain, and non-generic.
// ---------------------------------------------------------------------------

eq<Exact<typeof layer, (options?: Options) => Layer.Layer<MagicLink, never, Requirements>>>(true)

// ---------------------------------------------------------------------------
// Accepted: the plugin's own API, and a composed one.
// ---------------------------------------------------------------------------

const Todos = HttpApiGroup.make("todos").add(
  HttpApiEndpoint.get("listTodos", "/todos", { success: Schema.Array(Schema.String) })
)

const ComposedApi = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLinkApiGroup).add(Todos)

const composed = handlers(ComposedApi)
const standalone = handlers(MagicLinkApi)

// The identifier of the service produced follows the *consuming* API, and the
// requirements stay exactly `HandlerServices`.
eq<
  Exact<
    typeof composed,
    Layer.Layer<HttpApiGroup.Service<"app", "magicLink">, never, HandlerServices>
  >
>(true)
eq<
  Exact<
    typeof standalone,
    Layer.Layer<HttpApiGroup.Service<"effect-auth-magic-link", "magicLink">, never, HandlerServices>
  >
>(true)

// ---------------------------------------------------------------------------
// Rejected. Each `@ts-expect-error` below is the test.
// ---------------------------------------------------------------------------

/** Somebody else's group, sharing only the name. */
const Impostor = HttpApiGroup.make("magicLink").add(
  HttpApiEndpoint.get("ping", "/ping", { success: Schema.String })
)

// @ts-expect-error — `groups.magicLink` is not this plugin's group; the handlers
// would have been built against endpoints this API does not declare.
handlers(HttpApi.make("app").add(Impostor))

// @ts-expect-error — a re-prefixed group is a different group type, and the
// routes registered would not be the ones this API serves.
handlers(HttpApi.make("app").add(MagicLinkApiGroup).prefix("/api"))

// @ts-expect-error — there is no `magicLink` group to implement.
handlers(HttpApi.make("app").addHttpApi(AuthApi))

// ---------------------------------------------------------------------------
// The client: the two mutations, typed by the group's own schemas.
// ---------------------------------------------------------------------------

const client = MagicLinkClient.make({ baseUrl: "http://localhost:3000" })

// The argument is the payload alone — the reactivity keys are baked in — and the
// success and error channels are the endpoint's own. The user is the base
// model's public projection: this group is not parameterized by a deployment's
// custom user fields, and `GET /session` is where those are read.
eq<
  Exact<
    typeof client.signIn,
    Atom.AtomResultFn<MagicLinkClient.SignIn, Ok, RateLimited>
  >
>(true)
eq<
  Exact<
    typeof client.exchange,
    Atom.AtomResultFn<
      MagicLinkClient.Exchange,
      SessionWithUser,
      InvalidToken | SignUpDisabled | RateLimited
    >
  >
>(true)

const _verifyUrl: string = client.verifyUrl("a-token")

// A layer built with the plugin's own effect keeps its requirements plain.
const _plugin: Layer.Layer<MagicLink, never, Requirements> = layer({ disableSignUp: true })
const _handlersOfComposed: Layer.Layer<HttpApiGroup.Service<"app", "magicLink">, never, HandlerServices> = handlers(
  ComposedApi
)

export type { _handlersOfComposed, _plugin, _verifyUrl }
