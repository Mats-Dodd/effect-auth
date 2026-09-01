/**
 * What every suite that drives this library over HTTP reaches for.
 *
 * **Details**
 *
 * `test/fixtures.ts` holds the values a domain test needs; these are the three
 * that only make sense once there is a browser in front of the deployment — a
 * client bound to `AuthTest.TestApi`, an account already signed in on one, and
 * the `Max-Age` a response wrote a cookie with.
 *
 * A suite whose deployment serves an API of its own — the email-otp tests, the
 * custom-field ones — builds its own client from `TestHttpClient.makeClient`,
 * because {@link makeClient} names this library's test API. {@link maxAgeSeconds}
 * still serves them: a cookie is a cookie whichever API wrote it.
 */
import { Duration, Option } from "effect"
import type { Cookies, HttpClientResponse } from "effect/unstable/http"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPasswordText } from "../fixtures.js"

/**
 * A browser addressing this block's deployment, with a jar the test can read.
 */
export const makeClient = (options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.makeClient(AuthTest.TestApi, options)

/**
 * Registers an account and returns the browser that is signed in as it.
 *
 * **Gotchas**
 *
 * `email` is required rather than defaulted: every test in the block writes to
 * one database, so two of them signing `ada@example.com` up would collide on
 * the unique index instead of testing anything.
 */
export const signedUp = (email: string, options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.signedUp({ ...options, email, name: testName, password: testPasswordText })

/** Which cookie off a response {@link maxAgeSeconds} should read. */
type ReadCookie = (response: HttpClientResponse.HttpClientResponse) => Option.Option<Cookies.Cookie>

/**
 * The `Max-Age` a response's session cookie was written with, in seconds, and
 * `undefined` when it wrote no such cookie or wrote one without a `Max-Age`.
 *
 * **Gotchas**
 *
 * `read` is which cookie to look at: it defaults to the session cookie, and the
 * cache tests pass `TestHttpClient.responseCacheCookie` — or a closure over it,
 * where the cookie is the secure-prefixed one — to read the snapshot's instead.
 */
export const maxAgeSeconds = (
  response: HttpClientResponse.HttpClientResponse,
  read: ReadCookie = TestHttpClient.responseCookie
): number | undefined => {
  const cookie = read(response)
  if (Option.isNone(cookie)) return undefined
  const maxAge = cookie.value.options?.maxAge
  return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
}

/**
 * The completed half of a sign-in's two-status success.
 *
 * **Details**
 *
 * `signInEmail` answers `SessionWithUser` on 200 or `MfaRequired` on 202, so a
 * test that means "sign in" has to say which one it expected. Every suite here
 * runs a deployment with no factor plugin installed, where 202 is unreachable —
 * this turns the unreachable branch into a failed assertion instead of an
 * `undefined` two lines later.
 */
export const completeSignIn = <S, U>(
  result: { readonly _tag: "MfaRequired" } | { readonly user: U; readonly session: S }
): { readonly user: U; readonly session: S } => {
  if ("_tag" in result) {
    throw new Error("expected a completed sign-in; the deployment answered MfaRequired")
  }
  return result
}
