/**
 * The transactional e-mail seam.
 *
 * `effect-auth` never sends mail itself. It declares what must be sent and
 * hands the consumer a `Redacted` token plus the fully built link; delivery —
 * templating, provider, retries — belongs to the application.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Layer, Redacted } from "effect"
 * import { AuthEmails } from "effect-auth"
 *
 * const to = (address: string, subject: string) => (url: Redacted.Redacted<string>) =>
 *   Effect.log(`${subject} → ${address}: ${Redacted.value(url)}`)
 *
 * const ConsoleEmails = Layer.succeed(AuthEmails)({
 *   sendVerification: ({ url, user }) => to(user.email, "verify your address")(url),
 *   sendPasswordReset: ({ url, user }) => to(user.email, "reset your password")(url),
 *   // The first hop goes to the address the account has now …
 *   sendChangeEmailConfirmation: ({ newEmail, url, user }) =>
 *     to(user.email, `confirm the move to ${newEmail}`)(url),
 *   // … and the second to the one it is moving to.
 *   sendChangeEmailVerification: ({ newEmail, url }) => to(newEmail, "verify your new address")(url),
 *   sendDeleteAccountConfirmation: ({ url, user }) => to(user.email, "confirm account deletion")(url)
 * })
 * ```
 *
 * @since 0.1.0
 */
import type { Effect } from "effect"
import { Context, Option, Redacted } from "effect"
import type { EmailDeliveryError } from "../domain/Errors.js"
import type { User } from "../domain/Schema.js"
import { validateUrl } from "../http/OriginCheck.js"
import type { AuthConfigService } from "./AuthConfig.js"

/**
 * What an outgoing authentication e-mail carries.
 *
 * **Gotchas**
 *
 * `token` and `url` are `Redacted`: the link is a bearer credential for the
 * account, so it must not reach a log line or an error report. Unwrap with
 * `Redacted.value` at the point the message body is composed and nowhere else.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthEmail {
  /**
   * The recipient. Always the user the token was minted for.
   */
  readonly user: User
  /**
   * The raw single-use token. Only its hash is stored, so this value exists
   * exactly once, here.
   */
  readonly token: Redacted.Redacted
  /**
   * The link to put in the message, already built from `baseUrl` and the
   * configured path, with the token in its query string.
   */
  readonly url: Redacted.Redacted
}

/**
 * An {@link AuthEmail} about a change of address.
 *
 * **Gotchas**
 *
 * Two of these are sent, to two different mailboxes, and the difference is the
 * whole design of the flow — so read {@link AuthEmailsService.sendChangeEmailConfirmation}
 * and {@link AuthEmailsService.sendChangeEmailVerification} before writing the
 * templates. `user` is the account as it stands *now*, so `user.email` is always
 * the current address and {@link ChangeEmailEmail.newEmail} the proposed one.
 *
 * @category models
 * @since 0.1.0
 */
export interface ChangeEmailEmail extends AuthEmail {
  /** The address the person has asked to move the account to. */
  readonly newEmail: string
}

/**
 * The {@link AuthEmails} service definition — what an application implements to
 * deliver authentication e-mails.
 *
 * **Details**
 *
 * Every method may fail with `EmailDeliveryError`. The endpoints that trigger
 * them still answer `200` — whether an address exists must not be observable —
 * so a failure is a signal for your logs, not for the caller.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthEmailsService {
  /**
   * Sends the "confirm your address" message.
   */
  readonly sendVerification: (email: AuthEmail) => Effect.Effect<void, EmailDeliveryError>

  /**
   * Sends the "reset your password" message.
   */
  readonly sendPasswordReset: (email: AuthEmail) => Effect.Effect<void, EmailDeliveryError>

  /**
   * Sends the *first* hop of an e-mail change, to the address the account has
   * **now**.
   *
   * **Details**
   *
   * Deliver it to `email.user.email`, and say which address the account is being
   * moved to. This hop exists so that somebody who has taken over a session
   * cannot walk off with the account silently: the person who still holds the
   * current mailbox is told, and is the one who has to click.
   *
   * **Gotchas**
   *
   * Sent only when the current address is verified — an unverified one is no
   * evidence that anybody reads it, so the flow starts at the second hop
   * instead.
   */
  readonly sendChangeEmailConfirmation: (email: ChangeEmailEmail) => Effect.Effect<void, EmailDeliveryError>

  /**
   * Sends the *second* hop of an e-mail change, to the **new** address.
   *
   * **Gotchas**
   *
   * Deliver it to `email.newEmail`, never to `email.user.email`. Following this
   * link is what actually moves the account, and it proves the person controls
   * the mailbox they are moving it to.
   */
  readonly sendChangeEmailVerification: (email: ChangeEmailEmail) => Effect.Effect<void, EmailDeliveryError>

  /**
   * Sends the "confirm you want to delete your account" message.
   *
   * **Details**
   *
   * Only sent where `user.deleteUser.confirmByEmail` is on. Following the link
   * deletes the account, so the message should say so plainly and should not be
   * the only warning the person ever sees.
   */
  readonly sendDeleteAccountConfirmation: (email: AuthEmail) => Effect.Effect<void, EmailDeliveryError>
}

/**
 * The service an application implements to deliver authentication e-mails. See
 * {@link AuthEmailsService}.
 *
 * @category services
 * @since 0.1.0
 */
export class AuthEmails extends Context.Service<AuthEmails, AuthEmailsService>()("effect-auth/config/AuthEmails") {}

/**
 * Builds a link to `path` under the configured `baseUrl` carrying `token` in
 * its `token` query parameter.
 *
 * @category combinators
 * @since 0.1.0
 */
export const tokenUrl = (config: AuthConfigService, path: string, token: Redacted.Redacted): Redacted.Redacted => {
  const url = new URL(path, config.baseUrl)
  url.searchParams.set("token", Redacted.value(token))
  return Redacted.make(url.toString())
}

/**
 * The e-mail verification link for a token.
 *
 * @category combinators
 * @since 0.1.0
 */
export const verifyEmailUrl = (config: AuthConfigService, token: Redacted.Redacted): Redacted.Redacted =>
  tokenUrl(config, config.emailPaths.verifyEmail, token)

/**
 * The password reset link for a token.
 *
 * @category combinators
 * @since 0.1.0
 */
export const resetPasswordUrl = (config: AuthConfigService, token: Redacted.Redacted): Redacted.Redacted =>
  tokenUrl(config, config.emailPaths.resetPassword, token)

/**
 * The first-hop link of an e-mail change — the one sent to the current address.
 *
 * @category combinators
 * @since 0.1.0
 */
export const changeEmailConfirmUrl = (config: AuthConfigService, token: Redacted.Redacted): Redacted.Redacted =>
  tokenUrl(config, config.emailPaths.changeEmailConfirm, token)

/**
 * The second-hop link of an e-mail change — the one sent to the new address.
 *
 * **Gotchas**
 *
 * The new address is *not* in this URL, and must never be put there: it travels
 * in the token's server-side payload. A link that named it could be edited into
 * a link that moves the account somewhere else.
 *
 * @category combinators
 * @since 0.1.0
 */
export const changeEmailVerifyUrl = (config: AuthConfigService, token: Redacted.Redacted): Redacted.Redacted =>
  tokenUrl(config, config.emailPaths.changeEmailVerify, token)

/**
 * The account-deletion confirmation link.
 *
 * @category combinators
 * @since 0.1.0
 */
export const deleteAccountUrl = (config: AuthConfigService, token: Redacted.Redacted): Redacted.Redacted =>
  tokenUrl(config, config.emailPaths.deleteAccount, token)

/**
 * Appends the caller's landing page to an e-mailed link — after validating it,
 * again.
 *
 * **When to use**
 *
 * Wherever a flow puts a `callbackURL` a caller supplied into a link it is
 * about to mail: the reset and verification links, both hops of a change of
 * address. One combinator rather than one per module, so that the parameter
 * name a landing page reads is decided in a single place.
 *
 * **Gotchas**
 *
 * The HTTP layer is expected to have validated the candidate already, and this
 * second pass is deliberate: what goes in here ends up in a link sent to
 * somebody's mailbox, and an open redirect there is a phishing page with the
 * deployment's own name on it. A candidate that does not survive
 * `OriginCheck.validateUrl` is dropped rather than refused — the message is
 * worth sending without it.
 *
 * @category combinators
 * @since 0.1.0
 */
export const withCallbackUrl = (
  config: AuthConfigService,
  url: Redacted.Redacted,
  callbackURL: string | null | undefined
): Redacted.Redacted => {
  const validated = validateUrl(config, callbackURL)
  if (Option.isNone(validated)) return url
  const parsed = new URL(Redacted.value(url))
  parsed.searchParams.set("callbackURL", validated.value)
  return Redacted.make(parsed.toString())
}
