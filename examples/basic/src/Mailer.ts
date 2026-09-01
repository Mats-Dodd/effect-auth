/**
 * A development mailer: it prints the credential instead of delivering it.
 *
 * **Gotchas**
 *
 * The verification and reset links are bearer credentials for the account —
 * that is why `AuthEmail` hands them over as `Redacted`. Printing one is
 * appropriate for a local example and for nothing else. A real implementation
 * unwraps `email.url` only into the message body it hands to the transport.
 */
import { Effect, Layer, Redacted } from "effect"
import { AuthEmails, EmailOtp } from "effect-auth"

const send = (subject: string, to: string, url: Redacted.Redacted) =>
  Effect.log(`${subject} for ${to}: ${Redacted.value(url)}`)

const print = (subject: string) => (email: AuthEmails.AuthEmail) => send(subject, email.user.email, email.url)

export const layer: Layer.Layer<AuthEmails.AuthEmails> = Layer.succeed(AuthEmails.AuthEmails)({
  sendVerification: print("Verify your e-mail address"),
  sendPasswordReset: print("Reset your password"),
  // The first hop goes to the address the account has now, and says where it is
  // being moved to; the second goes to the new address, and is what moves it.
  sendChangeEmailConfirmation: (email) => send(`Confirm the move to ${email.newEmail}`, email.user.email, email.url),
  sendChangeEmailVerification: (email) => send("Verify your new e-mail address", email.newEmail, email.url),
  sendDeleteAccountConfirmation: print("Confirm deleting your account")
})

/**
 * The e-mail one-time-code plugin's mailer — a service of its own, not a method
 * on {@link layer}.
 *
 * **Details**
 *
 * This is the plugin convention, and the reason for it is visible in the
 * signature: `user` is `null` when the address has no account, because
 * `POST /auth/email-otp/send` must answer identically whether or not somebody
 * is registered. `AuthEmails` could not carry that shape without every existing
 * deployment having to implement it.
 *
 * **Gotchas**
 *
 * The code and the link spend the same row, so a message carrying both offers
 * two ways to finish one ceremony and answering either retires the other. The
 * code is the one to lead with: it works when the mail client rewrites links,
 * and it is what a person types on the device they are actually signing in on.
 */
export const emailOtpLayer: Layer.Layer<EmailOtp.EmailOtpEmails> = Layer.succeed(EmailOtp.EmailOtpEmails)({
  sendCode: ({ code, email, link, purpose, user }) =>
    Effect.log(
      `${subjectFor(purpose, user)} for ${email}: ${Redacted.value(code)}` +
        (link === null ? "" : ` (or follow ${Redacted.value(link)})`)
    )
})

/** One template, five purposes — and the sign-in one has two meanings. */
const subjectFor = (purpose: EmailOtp.EmailOtpPurpose, user: unknown): string => {
  switch (purpose) {
    case "signIn":
      return user === null ? "Create your account" : "Your sign-in code"
    case "verifyEmail":
      return "Verify your e-mail address"
    case "resetPassword":
      return "Reset your password"
    case "stepUp":
      return "Confirm it is you"
    case "changeEmail":
      return "Verify your new e-mail address"
  }
}
