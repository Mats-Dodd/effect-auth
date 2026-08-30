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
 * const ConsoleEmails = Layer.succeed(AuthEmails)({
 *   sendVerification: ({ url, user }) =>
 *     Effect.log(`verify ${user.email}: ${Redacted.value(url)}`),
 *   sendPasswordReset: ({ url, user }) =>
 *     Effect.log(`reset ${user.email}: ${Redacted.value(url)}`)
 * })
 * ```
 *
 * @since 1.0.0
 */
import type { Effect } from "effect"
import { Context, Redacted } from "effect"
import type { EmailDeliveryError } from "../domain/Errors.js"
import type { User } from "../domain/Schema.js"
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
 * @since 1.0.0
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
  readonly token: Redacted.Redacted<string>
  /**
   * The link to put in the message, already built from `baseUrl` and the
   * configured path, with the token in its query string.
   */
  readonly url: Redacted.Redacted<string>
}

/**
 * The {@link AuthEmails} service definition — what an application implements to
 * deliver authentication e-mails.
 *
 * **Details**
 *
 * Both methods may fail with `EmailDeliveryError`. The endpoints that trigger
 * them still answer `200` — whether an address exists must not be observable —
 * so a failure is a signal for your logs, not for the caller.
 *
 * @category models
 * @since 1.0.0
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
}

/**
 * The service an application implements to deliver authentication e-mails. See
 * {@link AuthEmailsService}.
 *
 * @category services
 * @since 1.0.0
 */
export class AuthEmails extends Context.Service<AuthEmails, AuthEmailsService>()("effect-auth/AuthEmails") {}

/**
 * Builds a link to `path` under the configured `baseUrl` carrying `token` in
 * its `token` query parameter.
 *
 * @category combinators
 * @since 1.0.0
 */
export const tokenUrl = (
  config: AuthConfigService,
  path: string,
  token: Redacted.Redacted<string>
): Redacted.Redacted<string> => {
  const url = new URL(path, config.baseUrl)
  url.searchParams.set("token", Redacted.value(token))
  return Redacted.make(url.toString())
}

/**
 * The e-mail verification link for a token.
 *
 * @category combinators
 * @since 1.0.0
 */
export const verifyEmailUrl = (
  config: AuthConfigService,
  token: Redacted.Redacted<string>
): Redacted.Redacted<string> => tokenUrl(config, config.emailPaths.verifyEmail, token)

/**
 * The password reset link for a token.
 *
 * @category combinators
 * @since 1.0.0
 */
export const resetPasswordUrl = (
  config: AuthConfigService,
  token: Redacted.Redacted<string>
): Redacted.Redacted<string> => tokenUrl(config, config.emailPaths.resetPassword, token)
