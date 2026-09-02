/**
 * The phone plugin, wired into a test deployment.
 *
 * **Details**
 *
 * The same shape `EmailOtpTest` has, with two additions a plugin that owns a
 * table needs: its migrations run over the *same* PGlite the rest of the
 * deployment uses ({@link layerStore}), and its `Authenticators` contribution
 * is installed **underneath** the deployment ({@link layerAuthenticators}),
 * because the reference is read when `Accounts` and the reclaim path are built
 * rather than per request. Nothing here is specific to testing except the
 * outbox and the gateway over it: the composition is exactly what a consumer
 * writes.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { PhoneTest } from "effect-auth/testing"
 *
 * layer(PhoneTest.layerHttp({ phone: { signIn: true, allowedCountries: ["1"] } }))("phone", (it) => {
 *   it.effect("signs a number in", () => …)
 * })
 * ```
 *
 * **Gotchas**
 *
 * `allowedCountries` defaults to the empty list, which refuses every number —
 * in a test exactly as in production. A test that means to send anything states
 * a country, and the one test that means to prove the default states none.
 *
 * @since 0.2.0
 */
import { Effect, Layer, Option, Redacted } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { baseUserModel } from "../domain/Schema.js"
import { layer as authenticatorsLayer } from "../domain/Authenticators.js"
import { AuthApi } from "../http/AuthApi.js"
import { PhoneApiGroup } from "../phone/Api.js"
import { handlers as phoneHandlers } from "../phone/Handlers.js"
import * as PhoneMigrations from "../phone/Migrations.js"
import type { Options as PhoneOptions, Phone, Requirements } from "../phone/Phone.js"
import {
  authenticators as phoneAuthenticators,
  layer as phoneLayer,
  SmsDeliveryError,
  SmsSender
} from "../phone/Phone.js"
import type { PhoneStore } from "../phone/Store.js"
import { layer as phoneStoreLayer } from "../phone/Store.js"
import type * as Database from "./Database.js"
import { smsKind, sms as smsRecord, TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * The kind the captured outbox records a message under.
 *
 * **Gotchas**
 *
 * `emails.tokenFor(PhoneTest.smsKind, number)` reads the *body* of the last
 * message sent to a number, because that is what the gateway was handed.
 * {@link codeOf} pulls the digits back out of it, and {@link codeFor} does both.
 *
 * @category constructors
 * @since 0.2.0
 */
export { smsKind } from "./TestEmails.js"

/**
 * The plugin's table, over whatever `SqlClient` the deployment is running on.
 *
 * **Gotchas**
 *
 * The migrations are `orDie`d rather than carried in the error channel: a test
 * whose schema will not build is broken rather than failing, and it is what
 * lets this layer be handed to `AuthTest.layerHttpApi`'s `extra`, which takes a
 * layer that cannot fail.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerStore: Layer.Layer<PhoneStore, never, SqlClient.SqlClient> = phoneStoreLayer.pipe(
  Layer.provide(Layer.orDie(PhoneMigrations.layer))
)

/**
 * The plugin's SMS gateway, implemented over the shared outbox.
 *
 * **Details**
 *
 * `TestEmails.record` is the seam that exists for this, and `TestEmails.sms`
 * builds the record: one outbox for mail and messages, so a phone assertion is
 * the same assertion an email-otp one is.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerSms: Layer.Layer<SmsSender, never, TestEmails> = Layer.effect(
  SmsSender,
  Effect.map(TestEmails, (outbox) => ({
    send: (message) =>
      Effect.mapError(outbox.record(smsRecord({ to: message.to, code: message.body, user: message.user })), (error) =>
        // The outbox reports the mail seam's failure; the plugin's gateway has
        // one of its own, and `delivery: "failing"` has to reach it as such.
        SmsDeliveryError.make({ reason: error.reason })
      )
  }))
)

/**
 * What a test may vary about a deployment serving phone numbers.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — the capabilities, the allowlist, the limits. */
  readonly phone?: PhoneOptions | undefined
}

/**
 * The plugin's service over a test deployment's own, with the outbox as its
 * gateway.
 *
 * **Gotchas**
 *
 * {@link layerSms} goes in under `Layer.fresh`, and that is load-bearing for
 * the reason `EmailOtpTest.layerEmailOtp` gives: `@effect/vitest` memoises
 * layers by object identity across a block and its nested variants, so without
 * it a nested `it.layer` would record its messages in the parent block's
 * outbox.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerPhone = (
  options?: PhoneOptions
): Layer.Layer<
  Phone | PhoneStore,
  never,
  Exclude<Requirements, SmsSender | PhoneStore> | SqlClient.SqlClient | TestEmails
> => phoneLayer(options).pipe(Layer.provide(Layer.fresh(layerSms)), Layer.provideMerge(layerStore))

/**
 * The plugin's `Authenticators` contribution, on the deployment's own database.
 *
 * **Details**
 *
 * `settings` is the deployment's own — the whole of `AuthTest.Settings`, not
 * just the plugin's section — because the contribution has to be built over the
 * *same* database the deployment is, and `Settings.database` is what names it.
 *
 * **When to use**
 *
 * Provided *underneath* `AuthTest.layer`, which is what {@link layer} does.
 * `Accounts.unlink` and the unproven-account reclaim read the reference when
 * they are built, so a contributor installed anywhere above them is one they
 * never see — the mistake this layer exists to make unmakeable.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerAuthenticators = (
  options?: PhoneOptions,
  settings?: AuthTest.Settings
): Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError> =>
  phoneAuthenticators(options).pipe(
    Layer.provide(layerStore),
    Layer.provide(AuthTest.layerDatabaseFor(baseUserModel, AuthTest.providerOf(settings)))
  )

/**
 * What `AuthTest.Settings.authenticators` installs, for the plugin itself.
 *
 * **Gotchas**
 *
 * The reference has to be provided twice, and that is not a quirk of the
 * harness: `Auth.layer` reads it when `Accounts` is built, and a plugin layer
 * composed *above* the deployment reads it when its own service is built, from
 * its own context. `Phone.Config.requireAlternateSecondFactor` is the one thing
 * in this plugin that reads it, and a deployment turning that on provides the
 * seam under `Phone.layer` as well as under `Auth.layer`.
 */
const seamFor = (options?: Options): Layer.Layer<never> =>
  options?.authenticators === undefined ? Layer.empty : authenticatorsLayer(options.authenticators)

/**
 * A whole test deployment with the phone plugin on top of it and its
 * contribution to the authenticator seam underneath.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  Phone | PhoneStore | Services | SqlClient.SqlClient | Database.TestDatabase | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  layerPhone(options?.phone).pipe(
    Layer.provide(seamFor(options)),
    Layer.provideMerge(AuthTest.layer(options).pipe(Layer.provide(layerAuthenticators(options?.phone, options))))
  )

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(PhoneApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", Phone | PhoneStore | HttpApiGroup.Service<"test-app", "phone">> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    Layer.merge(
      phoneHandlers(TestApi).pipe(Layer.provide(layerPhone(options?.phone).pipe(Layer.provide(seamFor(options))))),
      layerPhone(options?.phone).pipe(Layer.provide(seamFor(options)))
    )
  )

// -----------------------------------------------------------------------------
// Reading the outbox
// -----------------------------------------------------------------------------

/**
 * The digits out of a message body.
 *
 * **Gotchas**
 *
 * The gateway is handed a composed body rather than a bare code — that is the
 * seam's shape, and a deployment templates its own text through
 * `Phone.Config.message`. A test reading a code back out looks for the run of
 * digits, which the default template makes unambiguous.
 *
 * @category combinators
 * @since 0.2.0
 */
export const codeOf = (body: string): Option.Option<string> => {
  const match = /\d{4,10}/.exec(body)
  return match === null ? Option.none() : Option.some(match[0])
}

/**
 * The code out of the last message sent to a number.
 *
 * Fails with a defect when nothing was sent to it, or when what was sent
 * carries no code — in a test either is a broken assumption rather than a
 * condition to recover from.
 *
 * @category combinators
 * @since 0.2.0
 */
export const codeFor = (phoneNumber: string): Effect.Effect<string, never, TestEmails> =>
  Effect.gen(function* () {
    const outbox = yield* TestEmails
    const body = Redacted.value(yield* outbox.tokenFor(smsKind, phoneNumber))
    return yield* Option.match(codeOf(body), {
      onNone: () => Effect.die(new Error(`no code in the message sent to ${phoneNumber}: ${body}`)),
      onSome: Effect.succeed
    })
  })
