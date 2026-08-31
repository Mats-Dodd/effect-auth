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
 * A plugin's mailer is its own service with its own shape, so the outbox is not
 * tied to `AuthEmails`: {@link TestEmailsService.record} is the seam a plugin's
 * test layer implements its mailer over, and the recipient it records is a plain
 * address — which a plugin's mail may have without a user behind it at all.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Option, Redacted, Ref } from "effect"
import type { AuthEmail, ChangeEmailEmail } from "../config/AuthEmails.js"
import { AuthEmails } from "../config/AuthEmails.js"
import { EmailDeliveryError } from "../domain/Errors.js"
import type { User } from "../domain/Schema.js"

/**
 * What kind of e-mail was delivered.
 *
 * **Details**
 *
 * A plain string rather than a union: a plugin adds kinds of its own, and a
 * closed union here would mean every plugin's test harness had to widen a type
 * belonging to this library. The kinds this library itself records are the
 * constants below.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailKind = string

/**
 * The kind recorded for the "confirm your address" message.
 *
 * @category constructors
 * @since 1.0.0
 */
export const verificationKind: EmailKind = "verification"

/**
 * The kind recorded for the "reset your password" message.
 *
 * @category constructors
 * @since 1.0.0
 */
export const resetKind: EmailKind = "reset"

/**
 * The kind recorded for the first hop of an e-mail change — the one sent to the
 * address the account currently has.
 *
 * @category constructors
 * @since 1.0.0
 */
export const changeEmailConfirmationKind: EmailKind = "change-email-confirmation"

/**
 * The kind recorded for the second hop of an e-mail change — the one sent to
 * the **new** address.
 *
 * **Gotchas**
 *
 * `to` is that new address, so `emails.tokenFor(changeEmailVerificationKind,
 * newAddress)` is how a test reads the link, exactly as the person would.
 *
 * @category constructors
 * @since 1.0.0
 */
export const changeEmailVerificationKind: EmailKind = "change-email-verification"

/**
 * The kind recorded for the "confirm you want to delete your account" message.
 *
 * @category constructors
 * @since 1.0.0
 */
export const deleteAccountKind: EmailKind = "delete-account"

/**
 * One e-mail the application asked to have delivered.
 *
 * @category models
 * @since 1.0.0
 */
export interface SentEmail {
  /** What kind of message it was — see {@link verificationKind}. */
  readonly kind: EmailKind
  /**
   * Who it went to.
   *
   * **Details**
   *
   * Recorded separately from `user` because a plugin may mail an address that
   * belongs to nobody — a magic link to an unknown address, which must look
   * exactly like one to a known address.
   */
  readonly to: string
  /** The user it was about, or `null` when the flow does not know one. */
  readonly user: User | null
  /** The raw single-use token the link carries. */
  readonly token: Redacted.Redacted<string>
  /** The link itself. */
  readonly url: Redacted.Redacted<string>
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
   * Records one message, and then reports whatever this outbox's `delivery`
   * setting says.
   *
   * **When to use**
   *
   * From a plugin's own mailer layer, which is a service of its own shape:
   * implement it over this and the plugin's mail lands in the same outbox, with
   * the same failure behaviour, as the library's own.
   */
  readonly record: (email: SentEmail) => Effect.Effect<void, EmailDeliveryError>

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
  email.kind === kind && (address === undefined || normalise(email.to) === normalise(address))

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

      const record = (email: SentEmail) =>
        Ref.update(outbox, (sent) => [...sent, email]).pipe(
          Effect.andThen(
            delivery === "ok"
              ? Effect.void
              : Effect.fail(new EmailDeliveryError({ reason: "TestMailerRefused" }))
          )
        )

      /** The library's messages, which always know their user. */
      const recordAuthEmail = (kind: EmailKind) => (email: AuthEmail) =>
        record({ kind, to: email.user.email, user: email.user, token: email.token, url: email.url })

      /**
       * The second hop of an e-mail change, which is the one message this
       * library sends to an address the user does not (yet) have. Recording it
       * under `to: newEmail` is what lets a test read it the way its recipient
       * would.
       */
      const recordChangeEmailVerification = (email: ChangeEmailEmail) =>
        record({
          kind: changeEmailVerificationKind,
          to: email.newEmail,
          user: email.user,
          token: email.token,
          url: email.url
        })

      const last = (kind: EmailKind, address?: string) =>
        Effect.map(Ref.get(outbox), (sent) => {
          const matching = sent.filter((email) => matches(email, kind, address))
          return Option.fromUndefinedOr(matching[matching.length - 1])
        })

      return Context.make(TestEmails, {
        record,
        all: Ref.get(outbox),
        to: (address) =>
          Effect.map(
            Ref.get(outbox),
            (sent) => sent.filter((email) => normalise(email.to) === normalise(address))
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
          sendVerification: recordAuthEmail(verificationKind),
          sendPasswordReset: recordAuthEmail(resetKind),
          sendChangeEmailConfirmation: recordAuthEmail(changeEmailConfirmationKind),
          sendChangeEmailVerification: recordChangeEmailVerification,
          sendDeleteAccountConfirmation: recordAuthEmail(deleteAccountKind)
        })
      )
    })
  )
