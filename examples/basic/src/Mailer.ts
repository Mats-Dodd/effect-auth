/**
 * A development mailer: it prints the link instead of delivering it.
 *
 * **Gotchas**
 *
 * The verification and reset links are bearer credentials for the account —
 * that is why `AuthEmail` hands them over as `Redacted`. Printing one is
 * appropriate for a local example and for nothing else. A real implementation
 * unwraps `email.url` only into the message body it hands to the transport.
 */
import { Effect, Layer, Redacted } from "effect"
import { AuthEmails } from "effect-auth"

const print = (subject: string) => (email: AuthEmails.AuthEmail) =>
  Effect.log(`${subject} for ${email.user.email}: ${Redacted.value(email.url)}`)

export const layer: Layer.Layer<AuthEmails.AuthEmails> = Layer.succeed(AuthEmails.AuthEmails)({
  sendVerification: print("Verify your e-mail address"),
  sendPasswordReset: print("Reset your password")
})
