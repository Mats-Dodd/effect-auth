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
import { AuthEmails, MagicLink } from "effect-auth"

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

/**
 * The magic link plugin's mailer — a service of its own, not a method on
 * {@link layer}.
 *
 * **Details**
 *
 * This is the plugin convention, and the reason for it is visible in the
 * signature: `user` is `null` when the address has no account, because
 * `POST /auth/magic-link/sign-in` must answer identically whether or not
 * somebody is registered. `AuthEmails` could not carry that shape without every
 * existing deployment having to implement it.
 *
 * **Gotchas**
 *
 * Both messages have to go out — the one that signs somebody in and the one that
 * offers to create an account. Sending only the first would make delivery itself
 * the oracle the `200` is careful not to be.
 */
export const magicLinkLayer: Layer.Layer<MagicLink.MagicLinkEmails> = Layer.succeed(MagicLink.MagicLinkEmails)({
  sendMagicLink: ({ email, url, user }) =>
    send(user === null ? "Create your account" : "Your sign-in link", email, url)
})
