/**
 * The e-mail one-time-code plugin, wired into a test deployment.
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
 * import { EmailOtpTest } from "effect-auth/testing"
 *
 * layer(EmailOtpTest.layerHttp())("email-otp", (it) => {
 *   it.effect("signs a stranger in", () => …)
 * })
 * ```
 *
 * @since 0.2.0
 */
import { Effect, Layer, type Redacted } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Services } from "../config/Auth.js"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import { EmailOtpApiGroup } from "../email-otp/Api.js"
import { handlers as emailOtpHandlers } from "../email-otp/Handlers.js"
import {
  type EmailOtp,
  EmailOtpEmails,
  layer as emailOtpLayer,
  type Options as EmailOtpOptions,
  type Requirements
} from "../email-otp/EmailOtp.js"
import { AuthApi } from "../http/AuthApi.js"
import type * as Database from "./Database.js"
import { type EmailKind, type SentEmail, TestEmails } from "./TestEmails.js"
import { tokenOf } from "./TestHttpClient.js"
import * as AuthTest from "./TestLayer.js"

/**
 * The kind the captured outbox records a one-time code under.
 *
 * **Gotchas**
 *
 * `to` is the address the code was sent to, whether or not it belongs to
 * anybody, so `emails.tokenFor(EmailOtpTest.emailOtpKind, address)` reads a code
 * exactly as its recipient would. `token` is the code; `url` is the link that
 * spends the same row, and repeats the code when the purpose has no link.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpKind: EmailKind = "email-otp"

/**
 * The plugin's mailer, implemented over the shared outbox.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerEmails: Layer.Layer<EmailOtpEmails, never, TestEmails> = Layer.effect(
  EmailOtpEmails,
  Effect.map(TestEmails, (outbox) => ({
    sendCode: (email) =>
      outbox.record({
        kind: emailOtpKind,
        to: email.email,
        user: email.user,
        token: email.code,
        // A purpose with no link still has to answer `url`, and repeating the
        // code is the shape `TestEmails.sms` already uses for the same reason.
        url: email.link ?? email.code
      })
  }))
)

/**
 * What a test may vary about a deployment serving e-mail one-time codes.
 *
 * **Gotchas**
 *
 * `AuthTest.Settings` rather than `AuthTest.Options`: {@link TestApi} composes
 * this library's *base* auth group, so a deployment with custom user fields is
 * not something this harness can serve. Such a test builds its own API from
 * `makeAuthApi(model)` and adds `EmailOtpApiGroup` to it.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — digits, TTL, attempts, `disableSignUp`. */
  readonly emailOtp?: EmailOtpOptions | undefined
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
 * variant a new outbox of its own. Every code in the variant would then land in
 * the wrong outbox and its assertions would fail confusingly.
 * `emailOtpLayer(options)` is a fresh value per call and needs no such care.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerEmailOtp = (
  options?: EmailOtpOptions
): Layer.Layer<EmailOtp, never, Exclude<Requirements, EmailOtpEmails> | TestEmails> =>
  emailOtpLayer(options).pipe(Layer.provide(Layer.fresh(layerEmails)))

/**
 * A whole test deployment with the e-mail one-time-code plugin on top of it.
 *
 * **When to use**
 *
 * For the domain-level tests. {@link layerHttp} is the same deployment with the
 * endpoints in front of it.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  EmailOtp | Services | SqlClient.SqlClient | Database.TestDatabase | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> => layerEmailOtp(options?.emailOtp).pipe(Layer.provideMerge(AuthTest.layer(options)))

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(EmailOtpApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "emailOtp">> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    emailOtpHandlers(TestApi).pipe(Layer.provide(layerEmailOtp(options?.emailOtp)))
  )

// -----------------------------------------------------------------------------
// Reading the outbox

// -----------------------------------------------------------------------------

/**
 * The `count`-th code mailed to an address, once it has been.
 *
 * **When to use**
 *
 * Everywhere a test reads a code. Delivery is forked off the request path — the
 * send endpoint answers before the mailer has run, which is the whole point —
 * so the outbox is not guaranteed to be written by the time the call returns.
 * This yields to the scheduler until it is.
 *
 * **Gotchas**
 *
 * `count` is what makes a *resend* readable: waiting for "a code" would hand
 * back the one that was already there, so a test that asks twice asks for the
 * second. It defaults to one.
 *
 * It yields rather than sleeps, so it works under a `TestClock` that nobody is
 * advancing. It gives up after a bounded number of turns and fails as a defect:
 * a test that waited that long has a broken assumption, not a condition to
 * recover from.
 *
 * @category combinators
 * @since 0.2.0
 */
export const awaitDelivery = (address: string, count = 1): Effect.Effect<SentEmail, never, TestEmails> =>
  Effect.flatMap(TestEmails, (outbox) => {
    const attempt = (left: number): Effect.Effect<SentEmail> =>
      Effect.flatMap(outbox.to(address), (sent) => {
        const found = sent.filter((email) => email.kind === emailOtpKind)[count - 1]
        if (found !== undefined) return Effect.succeed(found)
        if (left === 0) {
          return Effect.die(`effect-auth/testing: no e-mail one-time code number ${count} reached ${address}`)
        }
        // Yield rather than sleep: the delivery is a fiber in the deployment's
        // scope, and handing the scheduler a turn is all it needs.
        return Effect.flatMap(Effect.yieldNow, () => attempt(left - 1))
      })
    return attempt(200)
  })

/**
 * The `count`-th code mailed to an address.
 *
 * @category combinators
 * @since 0.2.0
 */
export const awaitCode = (address: string, count = 1): Effect.Effect<Redacted.Redacted, never, TestEmails> =>
  Effect.map(awaitDelivery(address, count), (email) => email.token)

/**
 * The `token` query parameter of the `count`-th link mailed to an address.
 *
 * **Gotchas**
 *
 * Only the sign-in purpose mails a link; for the others `url` repeats the code
 * and this fails as a defect.
 *
 * @category combinators
 * @since 0.2.0
 */
export const awaitLinkToken = (address: string, count = 1): Effect.Effect<string, never, TestEmails> =>
  Effect.map(awaitDelivery(address, count), tokenOf)
