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
 * A suite whose deployment serves an API of its own — the magic-link tests, the
 * custom-field ones — builds its own client from `TestHttpClient.makeClient`,
 * because {@link makeClient} names this library's test API. {@link maxAgeSeconds}
 * still serves them: a cookie is a cookie whichever API wrote it.
 */
import { Duration, Option } from "effect"
import { dual } from "effect/Function"
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
export const signedUp: {
  (options?: TestHttpClient.ClientOptions): (email: string) => ReturnType<typeof TestHttpClient.signedUp>
  (email: string, options?: TestHttpClient.ClientOptions): ReturnType<typeof TestHttpClient.signedUp>
} = dual(
  // `options` is optional, so arity cannot tell the two call styles apart: a
  // one-argument call is data-first when what it holds is the address itself.
  (args) => typeof args[0] === "string",
  (email: string, options?: TestHttpClient.ClientOptions) =>
    TestHttpClient.signedUp({ ...options, email, name: testName, password: testPasswordText })
)

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
export const maxAgeSeconds: {
  (read?: ReadCookie): (response: HttpClientResponse.HttpClientResponse) => number | undefined
  (response: HttpClientResponse.HttpClientResponse, read?: ReadCookie): number | undefined
} = dual(
  // `read` is optional, so arity cannot tell the two call styles apart: a call
  // is data-first exactly when what it leads with is the response itself.
  (args) => args.length > 0 && typeof args[0] !== "function",
  (
    response: HttpClientResponse.HttpClientResponse,
    read: ReadCookie = TestHttpClient.responseCookie
  ): number | undefined => {
    const cookie = read(response)
    if (Option.isNone(cookie)) return undefined
    const maxAge = cookie.value.options?.maxAge
    return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
  }
)
