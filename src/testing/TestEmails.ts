/**
 * The captured outbox: a mailer that records what it was asked to deliver
 * instead of sending it.
 *
 * **Details**
 *
 * A verification or reset token exists exactly once, in the message that
 * carries it — nothing but its hash is stored. This module is how a test reads
 * that token, the way a person reads it out of their inbox.
 *
 * Every query is scoped by recipient. A suite that shares one deployment
 * between its tests has one outbox between them too, so "the last reset
 * e-mail" is only a well-defined thing to ask for once an address is named.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Option, Redacted, Ref } from "effect"
import type { AuthEmail } from "../config/AuthEmails.js"
import { AuthEmails } from "../config/AuthEmails.js"
import { EmailDeliveryError } from "../domain/Errors.js"

/**
 * Which of the two authentication e-mails was delivered.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailKind = "verification" | "reset"

/**
 * One e-mail the application asked to have delivered.
 *
 * @category models
 * @since 1.0.0
 */
export interface SentEmail extends AuthEmail {
  readonly kind: EmailKind
}

/**
 * Whether the mailer accepts what it is handed, or records it and then reports
 * a delivery failure.
 *
 * **When to use**
 *
 * `"failing"` is how a test proves that a failed delivery is invisible to the
 * caller: the endpoints that send mail still answer `200`, because whether an
 * address exists must not be observable.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailDelivery = "ok" | "failing"

/**
 * The captured outbox. See {@link TestEmails}.
 *
 * **Example**
 *
 * ```ts
 * import { Effect } from "effect"
 * import { TestEmails } from "effect-auth/testing"
 *
 * const token = Effect.gen(function*() {
 *   const emails = yield* TestEmails.TestEmails
 *   return yield* emails.tokenFor("reset", "ada@example.com")
 * })
 * ```
 *
 * @category models
 * @since 1.0.0
 */
export interface TestEmailsService {
  /**
   * Every e-mail delivered so far, oldest first.
   */
  readonly all: Effect.Effect<ReadonlyArray<SentEmail>>

  /**
   * Every e-mail delivered to one address, oldest first.
   *
   * **When to use**
   *
   * In a suite whose tests share a deployment, this is the assertion that
   * survives a concurrent sibling: `emails.to(address)` counts what *this*
   * test caused, where `emails.all` counts what the whole file did.
   */
  readonly to: (address: string) => Effect.Effect<ReadonlyArray<SentEmail>>

  /**
   * The most recent e-mail of a kind, optionally narrowed to one recipient, or
   * `None` when none was sent.
   */
  readonly last: (kind: EmailKind, address?: string) => Effect.Effect<Option.Option<SentEmail>>

  /**
   * The raw token from the most recent e-mail of a kind, optionally narrowed to
   * one recipient.
   *
   * Fails with a defect when no such e-mail was sent — in a test that is a
   * broken assumption, not a condition to recover from.
   */
  readonly tokenFor: (kind: EmailKind, address?: string) => Effect.Effect<Redacted.Redacted<string>>

  /**
   * Empties the outbox.
   */
  readonly clear: Effect.Effect<void>
}

/**
 * The captured outbox. See {@link TestEmailsService}.
 *
 * @category services
 * @since 1.0.0
 */
export class TestEmails extends Context.Service<TestEmails, TestEmailsService>()(
  "effect-auth/testing/TestEmails"
) {}

const normalise = (address: string): string => address.trim().toLowerCase()

const matches = (email: SentEmail, kind: EmailKind, address: string | undefined): boolean =>
  email.kind === kind && (address === undefined || normalise(email.user.email) === normalise(address))

/**
 * The capturing mailer, providing both {@link TestEmails} and the `AuthEmails`
 * seam that `Auth.layer` requires.
 *
 * **Details**
 *
 * `delivery` decides what the seam reports back to the library. Either way the
 * message is recorded first, so a test can assert on what *would* have gone out
 * even when the delivery failed.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerEmails = (
  delivery: EmailDelivery = "ok"
): Layer.Layer<TestEmails | AuthEmails> =>
  Layer.effectContext(
    Effect.gen(function*() {
      const outbox = yield* Ref.make<ReadonlyArray<SentEmail>>([])

      const record = (kind: EmailKind) => (email: AuthEmail) =>
        Ref.update(outbox, (sent) => [...sent, { ...email, kind }]).pipe(
          Effect.andThen(
            delivery === "ok"
              ? Effect.void
              : Effect.fail(new EmailDeliveryError({ reason: "TestMailerRefused" }))
          )
        )

      const last = (kind: EmailKind, address?: string) =>
        Effect.map(Ref.get(outbox), (sent) => {
          const matching = sent.filter((email) => matches(email, kind, address))
          return Option.fromUndefinedOr(matching[matching.length - 1])
        })

      return Context.make(TestEmails, {
        all: Ref.get(outbox),
        to: (address) =>
          Effect.map(
            Ref.get(outbox),
            (sent) => sent.filter((email) => normalise(email.user.email) === normalise(address))
          ),
        last,
        tokenFor: (kind, address) =>
          Effect.flatMap(
            last(kind, address),
            Option.match({
              onNone: () =>
                Effect.die(
                  new Error(
                    `effect-auth/testing: no ${kind} e-mail was sent${
                      address === undefined ? "" : ` to ${address}`
                    }`
                  )
                ),
              onSome: (email) => Effect.succeed(email.token)
            })
          ),
        clear: Ref.set(outbox, [])
      }).pipe(
        Context.add(AuthEmails, {
          sendVerification: record("verification"),
          sendPasswordReset: record("reset")
        })
      )
    })
  )
