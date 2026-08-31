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

const send = (subject: string, to: string, url: Redacted.Redacted<string>) =>
  Effect.log(`${subject} for ${to}: ${Redacted.value(url)}`)

const print = (subject: string) => (email: AuthEmails.AuthEmail) => send(subject, email.user.email, email.url)

export const layer: Layer.Layer<AuthEmails.AuthEmails> = Layer.succeed(AuthEmails.AuthEmails)({
  sendVerification: print("Verify your e-mail address"),
  sendPasswordReset: print("Reset your password"),
  // The first hop goes to the address the account has now, and says where it is
  // being moved to; the second goes to the new address, and is what moves it.
  sendChangeEmailConfirmation: (email) =>
    send(`Confirm the move to ${email.newEmail}`, email.user.email, email.url),
  sendChangeEmailVerification: (email) => send("Verify your new e-mail address", email.newEmail, email.url),
  sendDeleteAccountConfirmation: print("Confirm deleting your account")
})
