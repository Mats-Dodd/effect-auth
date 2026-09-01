/**
 * The magic link plugin, wired into a test deployment.
 *
 * **Details**
 *
 * This is what a plugin's test harness looks like: a mailer implemented over the
 * shared outbox ({@link layerEmails}), a layer that adds the plugin's service to
 * `AuthTest.layer`'s deployment ({@link layer}), an API that composes the
 * plugin's group beside this library's ({@link TestApi}), and the whole server
 * stack for it ({@link layerHttp}). Nothing here is specific to testing except
 * the outbox: the composition is exactly what a consumer writes.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { MagicLinkTest } from "effect-auth/testing"
 *
 * layer(MagicLinkTest.layerHttp())("magic-link", (it) => {
 *   it.effect("signs a stranger in", () => …)
 * })
 * ```
 *
 * @since 0.1.0
 */
import type { PgliteClient } from "@effect/sql-pglite"
import { Effect, Layer } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { AuthApi } from "../http/AuthApi.js"
import { MagicLinkApiGroup } from "../magic-link/Api.js"
import { handlers as magicLinkHandlers } from "../magic-link/Handlers.js"
import {
  layer as magicLinkLayer,
  type MagicLink,
  MagicLinkEmails,
  type Options as MagicLinkOptions,
  type Requirements
} from "../magic-link/MagicLink.js"
import { type EmailKind, TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * The kind the captured outbox records a magic link under.
 *
 * **Gotchas**
 *
 * `to` is the address the link was sent to, whether or not it belongs to
 * anybody, so `emails.tokenFor(MagicLinkTest.magicLinkKind, address)` is how a
 * test reads a link exactly as its recipient would.
 *
 * @category constructors
 * @since 0.1.0
 */
export const magicLinkKind: EmailKind = "magic-link"

/**
 * The plugin's mailer, implemented over the shared outbox.
 *
 * **Details**
 *
 * `TestEmails.record` is the seam that exists for this: a plugin's mailer is a
 * service of its own shape, and implementing it here puts its messages in the
 * same outbox — with the same `delivery: "failing"` behaviour — as the library's.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerEmails: Layer.Layer<MagicLinkEmails, never, TestEmails> = Layer.effect(
  MagicLinkEmails,
  Effect.map(TestEmails, (outbox) => ({
    sendMagicLink: (email) =>
      outbox.record({
        kind: magicLinkKind,
        to: email.email,
        user: email.user,
        token: email.token,
        url: email.url
      })
  }))
)

/**
 * What a test may vary about a deployment serving magic links.
 *
 * **Gotchas**
 *
 * `AuthTest.Settings` rather than `AuthTest.Options`: {@link TestApi} composes
 * this library's *base* auth group, so a deployment with custom user fields is
 * not something this harness can serve. Such a test builds its own API from
 * `makeAuthApi(model)` and adds `MagicLinkApiGroup` to it.
 *
 * @category models
 * @since 0.1.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — TTL, `disableSignUp`, `revokeUnprovenAccounts`. */
  readonly magicLink?: MagicLinkOptions | undefined
}

/**
 * The plugin's service over a test deployment's own, with the outbox as its
 * mailer.
 *
 * **Gotchas**
 *
 * {@link layerEmails} goes in under `Layer.fresh`, and that is load-bearing.
 * `@effect/vitest` memoises layers by object identity across a block and its
 * nested `it.layer` variants; `layerEmails` is a module-level constant, so
 * without `fresh` a nested variant would reuse the *parent's* build of it —
 * bound to the parent's `TestEmails` outbox — while `AuthTest.layer` hands the
 * variant a new outbox of its own. Every magic-link mail in the variant would
 * then land in the wrong outbox and its assertions would fail confusingly.
 * `magicLinkLayer(options)` is a fresh value per call and needs no such care.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerMagicLink = (
  options?: MagicLinkOptions
): Layer.Layer<MagicLink, never, Exclude<Requirements, MagicLinkEmails> | TestEmails> =>
  magicLinkLayer(options).pipe(Layer.provide(Layer.fresh(layerEmails)))

/**
 * A whole test deployment with the magic link plugin on top of it.
 *
 * **When to use**
 *
 * For the domain-level tests. {@link layerHttp} is the same deployment with the
 * endpoints in front of it.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  MagicLink | Services | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> => layerMagicLink(options?.magicLink).pipe(Layer.provideMerge(AuthTest.layer(options)))

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.1.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(MagicLinkApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * **Details**
 *
 * The plugin's handler layer goes in through `AuthTest.layerHttpApi`'s third
 * parameter, which provides it the *same* deployment build the auth handlers get
 * — so both groups read one `Sessions`, one `UserStore` and one rate limiter.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "magicLink">> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    magicLinkHandlers(TestApi).pipe(Layer.provide(layerMagicLink(options?.magicLink)))
  )
