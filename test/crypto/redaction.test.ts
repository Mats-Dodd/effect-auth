/**
 * The redaction test, written before the implementations it guards.
 *
 * Nothing in `src/crypto` may put a plaintext password or a raw token where a
 * log line, a `toString`, a JSON body or a rendered `Cause` can reach it. The
 * assertions below are deliberately about *rendering*, not about types: a
 * `Redacted<string>` that gets unwrapped one frame too early still typechecks.
 */
import { assert, describe, it, layer } from "@effect/vitest"
import { Cause, Effect, Layer, Logger, Option, Redacted } from "effect"
import * as PasswordHasher from "../../src/crypto/PasswordHasher.js"
import * as Token from "../../src/crypto/Token.js"
import { layerWebCrypto } from "../../src/internal/crypto.js"

const plaintext = "correct horse battery staple"

const captureLogs = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.suspend(() => {
    const lines: Array<string> = []
    const logger = Logger.formatLogFmt.pipe(Logger.map((line) => void lines.push(line)))
    // Exactly what `Logger.layer([logger])` installs — the reference holding the
    // fiber's logger set — provided as a service rather than as a layer, so
    // nothing here depends on a scope this helper does not own.
    return effect.pipe(
      Effect.provideService(Logger.CurrentLoggers, new Set([logger])),
      Effect.map((value) => ({ value, lines }))
    )
  })

describe("crypto/redaction", () => {
  it.effect("renders a redacted password as <redacted> in a log line", () =>
    Effect.gen(function* () {
      const password = Redacted.make(plaintext)

      const { lines } = yield* captureLogs(
        Effect.log("hashing password", { password }).pipe(Effect.annotateLogs("password", password))
      )

      assert.strictEqual(lines.length, 1)
      const line = lines[0]!
      assert.notInclude(line, plaintext)
      assert.notInclude(line, "correct")
      assert.include(line, "<redacted>")
    })
  )

  it("renders a redacted password as <redacted> through String and JSON", () => {
    const password = Redacted.make(plaintext)

    // `Redacted` gets its `toString` from `Inspectable` at runtime, but its
    // published interface does not declare one, so the type-aware rules below
    // see `Object.prototype.toString`. Stringifying a `Redacted` is precisely
    // the leak this test exists to catch, so the calls stay as written.
    // oxlint-disable-next-line typescript/no-base-to-string
    assert.strictEqual(String(password), "<redacted>")
    // oxlint-disable-next-line typescript/no-base-to-string, typescript/restrict-template-expressions
    assert.strictEqual(`${password}`, "<redacted>")
    assert.notInclude(JSON.stringify({ password }), plaintext)
    assert.strictEqual(Redacted.value(password), plaintext)
  })
})

layer(Token.layer.pipe(Layer.provide(layerWebCrypto)))("crypto/redaction (tokens)", (it) => {
  it.effect("mints tokens that never render in plaintext", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const token = yield* tokens.generateToken
      const raw = Redacted.value(token)

      assert.strictEqual(raw.length, Token.tokenLength)
      // Same false positive as above: the rendering is the assertion.
      // oxlint-disable-next-line typescript/no-base-to-string
      assert.strictEqual(String(token), "<redacted>")

      const { lines } = yield* captureLogs(
        Effect.log("issued session token", { token }).pipe(Effect.annotateLogs("token", token))
      )

      assert.strictEqual(lines.length, 1)
      assert.notInclude(lines[0]!, raw)
      assert.include(lines[0]!, "<redacted>")
    })
  )
})

layer(PasswordHasher.layerScrypt().pipe(Layer.provide(layerWebCrypto)))("crypto/redaction (hash failures)", (it) => {
  it.effect("keeps the plaintext out of a rendered PasswordHashError", () =>
    Effect.gen(function* () {
      const hasher = yield* PasswordHasher.PasswordHasher
      const password = Redacted.make(plaintext)

      const cause = yield* Effect.flatMap(Effect.exit(hasher.verify(password, "this-is-not-a-hash")), (exit) =>
        exit._tag === "Failure" ? Effect.succeed(exit.cause) : Effect.die("expected a failure")
      )

      const rendered = Cause.pretty(cause)
      assert.notInclude(rendered, plaintext)
      assert.notInclude(rendered, "correct")

      const failure = Option.getOrThrow(Cause.findErrorOption(cause))
      assert.strictEqual(failure._tag, "PasswordHashError")
      // `JSON.stringify` is the renderer under test, not a codec choice: an
      // error that reaches a JSON body goes through exactly this, and a schema
      // encode would assert about a different string than the one that leaks.
      // oxlint-disable-next-line effecttsgo/prefer-schema-over-json
      assert.notInclude(JSON.stringify(failure), plaintext)
      assert.notInclude(String(failure), plaintext)

      const { lines } = yield* captureLogs(Effect.logError("hash failed", failure))
      assert.strictEqual(lines.length, 1)
      assert.notInclude(lines[0]!, plaintext)
    })
  )
})

layer(PasswordHasher.layerScrypt({ N: 1024, r: 8 }).pipe(Layer.provide(layerWebCrypto)))(
  "crypto/redaction (hashing)",
  (it) => {
    it.effect("keeps the plaintext out of a hash it produced", () =>
      Effect.gen(function* () {
        const hasher = yield* PasswordHasher.PasswordHasher
        const hash = yield* hasher.hash(Redacted.make(plaintext))

        assert.notInclude(hash, plaintext)
        assert.notInclude(hash, "correct")
      })
    )
  }
)
