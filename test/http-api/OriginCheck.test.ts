import { assert, describe, it } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import {
  checkOrigin,
  claimedOrigin,
  isPathRelative,
  isTrustedOrigin,
  originOf,
  resolveUrl,
  safeMethods,
  trustedOrigins,
  validateUrl
} from "../../src/http/OriginCheck.js"

const baseUrl = "https://app.example.com"

const config = (trusted: ReadonlyArray<string> = []): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl,
    secret: Redacted.make("test-secret-at-least-32-bytes-long"),
    trustedOrigins: trusted
  })

const request = (options: { readonly method?: string; readonly headers?: Record<string, string> }) =>
  HttpServerRequest.fromWeb(
    new Request(`${baseUrl}/auth/sign-out`, {
      method: options.method ?? "POST",
      headers: options.headers ?? {}
    })
  )

const checking = (
  options: { readonly method?: string; readonly headers?: Record<string, string> },
  trusted: ReadonlyArray<string> = []
) =>
  Effect.result(
    checkOrigin(config(trusted)).pipe(Effect.provideService(HttpServerRequest.HttpServerRequest, request(options)))
  )

describe("http/OriginCheck", () => {
  describe("origins", () => {
    it("reads the origin of an absolute URL and nothing else", () => {
      assert.deepStrictEqual(originOf("https://app.example.com/a/b?c=d"), Option.some(baseUrl))
      assert.deepStrictEqual(originOf("https://app.example.com:8443/"), Option.some("https://app.example.com:8443"))
      assert.deepStrictEqual(originOf("/relative"), Option.none())
      assert.deepStrictEqual(originOf("not a url"), Option.none())
      assert.deepStrictEqual(originOf(""), Option.none())
    })

    it('gives no origin to a scheme that has none, so "null" is never trusted', () => {
      // Every one of these parses, and every one of them has the *origin
      // string* "null". Admitting that would make `Origin: null` — a sandboxed
      // iframe, which `claimedOrigin` exists to refuse — trusted, and would let
      // `resolveUrl` send a browser to a `data:` URL.
      assert.deepStrictEqual(originOf("javascript:alert(1)"), Option.none())
      assert.deepStrictEqual(originOf("data:text/html,<script>x</script>"), Option.none())
      assert.deepStrictEqual(originOf("file:///etc/passwd"), Option.none())
      assert.deepStrictEqual(originOf("null"), Option.none())

      // Configuration rejects an opaque trusted origin at startup.
      assert.throws(() => config(["data:text/html,evil"]), /trustedOrigins\[0\]/)
    })

    it("always trusts the baseUrl origin, plus whatever is configured", () => {
      const origins = trustedOrigins(config(["https://admin.example.com/console"]))
      assert.deepStrictEqual([...origins].sort(), ["https://admin.example.com", "https://app.example.com"])
      assert.throws(() => config(["nonsense"]), /trustedOrigins\[0\]/)
    })

    it("compares by origin, never by prefix", () => {
      const c = config()
      assert.isTrue(isTrustedOrigin(c, baseUrl))
      assert.isTrue(isTrustedOrigin(c, "https://app.example.com/deep/path"))
      // The classic prefix bug: a longer host that starts with the trusted one.
      assert.isFalse(isTrustedOrigin(c, "https://app.example.com.evil.test"))
      // A different scheme or port is a different origin.
      assert.isFalse(isTrustedOrigin(c, "http://app.example.com"))
      assert.isFalse(isTrustedOrigin(c, "https://app.example.com:8443"))
    })
  })

  describe("isPathRelative", () => {
    it("accepts a path and refuses everything that only looks like one", () => {
      assert.isTrue(isPathRelative("/"))
      assert.isTrue(isPathRelative("/welcome?next=1"))
      assert.isFalse(isPathRelative("//evil.test"))
      assert.isFalse(isPathRelative("/\\evil.test"))
      assert.isFalse(isPathRelative("relative"))
      assert.isFalse(isPathRelative("https://evil.test"))
    })

    it("documents the parser quirk it exists for", () => {
      // WHATWG URL folds a backslash onto a slash for http(s) schemes, so this
      // candidate is protocol-relative however much it looks like a path.
      assert.strictEqual(new URL("/\\evil.test", baseUrl).origin, "https://evil.test")
    })
  })

  describe("resolveUrl", () => {
    it("falls back to baseUrl when nothing was supplied", () => {
      const c = config()
      assert.strictEqual(resolveUrl(c, undefined), baseUrl)
      assert.strictEqual(resolveUrl(c, null), baseUrl)
      assert.strictEqual(resolveUrl(c, ""), baseUrl)
    })

    it("resolves a path against baseUrl", () => {
      const c = config()
      assert.strictEqual(resolveUrl(c, "/welcome"), "https://app.example.com/welcome")
      assert.strictEqual(resolveUrl(c, "/welcome?next=%2Fhome"), "https://app.example.com/welcome?next=%2Fhome")
    })

    it("keeps an absolute URL on a trusted origin", () => {
      const c = config(["https://admin.example.com"])
      assert.strictEqual(resolveUrl(c, "https://admin.example.com/console"), "https://admin.example.com/console")
      assert.strictEqual(resolveUrl(c, `${baseUrl}/welcome`), `${baseUrl}/welcome`)
    })

    it("refuses an untrusted absolute URL", () => {
      const c = config()
      assert.strictEqual(resolveUrl(c, "https://evil.test/phish"), baseUrl)
      assert.strictEqual(resolveUrl(c, "https://app.example.com.evil.test/phish"), baseUrl)
      assert.strictEqual(resolveUrl(c, "javascript:alert(1)"), baseUrl)
      assert.strictEqual(resolveUrl(c, "data:text/html,<script>1</script>"), baseUrl)
      assert.strictEqual(resolveUrl(c, "not a url at all"), baseUrl)
    })

    it("refuses every spelling of a protocol-relative URL", () => {
      const c = config()
      assert.strictEqual(resolveUrl(c, "//evil.test"), baseUrl)
      assert.strictEqual(resolveUrl(c, "//evil.test/path"), baseUrl)
      // Backslashes: the WHATWG parser treats these as slashes, so each of them
      // resolves to https://evil.test/ if the guard only looks for "//".
      assert.strictEqual(resolveUrl(c, "/\\evil.test"), baseUrl)
      assert.strictEqual(resolveUrl(c, "/\\/evil.test"), baseUrl)
      assert.strictEqual(resolveUrl(c, "\\/\\/evil.test"), baseUrl)
      assert.strictEqual(resolveUrl(c, "\\\\evil.test"), baseUrl)
      assert.strictEqual(resolveUrl(c, "/\t/evil.test"), baseUrl)
    })
  })

  describe("validateUrl", () => {
    it("distinguishes 'nothing supplied' from 'refused'", () => {
      const c = config()
      assert.deepStrictEqual(validateUrl(c, undefined), Option.none())
      assert.deepStrictEqual(validateUrl(c, ""), Option.none())
      assert.deepStrictEqual(validateUrl(c, "https://evil.test"), Option.none())
      assert.deepStrictEqual(validateUrl(c, "/\\evil.test"), Option.none())
      assert.deepStrictEqual(validateUrl(c, "/welcome"), Option.some("https://app.example.com/welcome"))
    })

    it("accepts the baseUrl itself", () => {
      assert.deepStrictEqual(validateUrl(config(), baseUrl), Option.some(baseUrl))
    })
  })

  describe("claimedOrigin", () => {
    it("prefers the Origin header", () => {
      assert.deepStrictEqual(
        claimedOrigin({ origin: "https://other.test", referer: "https://app.example.com/page" }),
        Option.some("https://other.test")
      )
    })

    it("falls back to the origin of the Referer", () => {
      assert.deepStrictEqual(claimedOrigin({ referer: "https://app.example.com/page?x=1" }), Option.some(baseUrl))
    })

    it("answers None only when the request claims nothing at all", () => {
      assert.deepStrictEqual(claimedOrigin({}), Option.none())
      assert.deepStrictEqual(claimedOrigin({ origin: "", referer: "" }), Option.none())
    })

    it("treats Origin: null as a claim, not as an absence", () => {
      assert.deepStrictEqual(claimedOrigin({ origin: "null" }), Option.some("null"))
      assert.isFalse(isTrustedOrigin(config(), "null"))
    })
  })

  describe("checkOrigin", () => {
    it.effect("skips the read-only methods", () =>
      Effect.gen(function* () {
        assert.deepStrictEqual([...safeMethods].sort(), ["GET", "HEAD", "OPTIONS"])
        for (const method of ["GET", "HEAD", "OPTIONS"]) {
          const result = yield* checking({ method, headers: { origin: "https://evil.test" } })
          assert.isTrue(result._tag === "Success", method)
        }
      })
    )

    it.effect("allows a request that claims no origin", () =>
      Effect.gen(function* () {
        const result = yield* checking({})
        assert.isTrue(result._tag === "Success")
      })
    )

    it.effect("allows a trusted claimed origin, by header or by referer", () =>
      Effect.gen(function* () {
        const byOrigin = yield* checking({ headers: { origin: baseUrl } })
        assert.isTrue(byOrigin._tag === "Success")

        const byReferer = yield* checking({ headers: { referer: `${baseUrl}/page` } })
        assert.isTrue(byReferer._tag === "Success")

        const byConfigured = yield* checking({ headers: { origin: "https://admin.example.com" } }, [
          "https://admin.example.com"
        ])
        assert.isTrue(byConfigured._tag === "Success")
      })
    )

    it.effect("refuses an untrusted claimed origin", () =>
      Effect.gen(function* () {
        const result = yield* checking({ headers: { origin: "https://evil.test" } })
        assert.isTrue(result._tag === "Failure")
        if (result._tag === "Failure") {
          assert.strictEqual(result.failure._tag, "Unauthorized")
        }
      })
    )

    it.effect("refuses a look-alike host", () =>
      Effect.gen(function* () {
        const result = yield* checking({ headers: { origin: "https://app.example.com.evil.test" } })
        assert.isTrue(result._tag === "Failure")
      })
    )

    it.effect("refuses Origin: null — a sandboxed iframe is a browser, and it is not us", () =>
      Effect.gen(function* () {
        const result = yield* checking({ headers: { origin: "null" } })
        assert.isTrue(result._tag === "Failure")
      })
    )

    it.effect("refuses an unparseable Referer when there is no Origin", () =>
      Effect.gen(function* () {
        const result = yield* checking({ headers: { referer: "about:blank" } })
        assert.isTrue(result._tag === "Failure")
      })
    )
  })
})
