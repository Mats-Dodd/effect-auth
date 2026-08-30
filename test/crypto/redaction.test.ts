/**
 * The redaction test, written before the implementations it guards.
 *
 * Nothing in `src/crypto` may put a plaintext password or a raw token where a
 * log line, a `toString`, a JSON body or a rendered `Cause` can reach it. The
 * assertions below are deliberately about *rendering*, not about types: a
 * `Redacted<string>` that gets unwrapped one frame too early still typechecks.
 */
import { assert, describe, it } from "@effect/vitest"
import { Cause, Effect, Logger, Redacted } from "effect"
import * as PasswordHasher from "../../src/crypto/PasswordHasher.js"
import * as Token from "../../src/crypto/Token.js"
import type { PasswordHashError } from "../../src/domain/Errors.js"

const plaintext = "correct horse battery staple"

const captureLogs = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.suspend(() => {
    const lines: Array<string> = []
    const logger = Logger.formatLogFmt.pipe(Logger.map((line) => void lines.push(line)))
    return effect.pipe(
      Effect.provide(Logger.layer([logger])),
      Effect.map((value) => ({ value, lines }))
    )
  })

describe("crypto/redaction", () => {
  it.effect("renders a redacted password as <redacted> in a log line", () =>
    Effect.gen(function*() {
      const password = Redacted.make(plaintext)

      const { lines } = yield* captureLogs(
        Effect.log("hashing password", { password }).pipe(
          Effect.annotateLogs("password", password)
        )
      )

      assert.strictEqual(lines.length, 1)
      const line = lines[0]!
      assert.notInclude(line, plaintext)
      assert.notInclude(line, "correct")
      assert.include(line, "<redacted>")
    }))

  it("renders a redacted password as <redacted> through String and JSON", () => {
    const password = Redacted.make(plaintext)

    assert.strictEqual(String(password), "<redacted>")
    assert.strictEqual(`${password}`, "<redacted>")
    assert.notInclude(JSON.stringify({ password }), plaintext)
    assert.strictEqual(Redacted.value(password), plaintext)
  })

  it.effect("mints tokens that never render in plaintext", () =>
    Effect.gen(function*() {
      const tokens = yield* Token.Token
      const token = yield* tokens.generateToken
      const raw = Redacted.value(token)

      assert.strictEqual(raw.length, Token.tokenLength)
      assert.strictEqual(String(token), "<redacted>")

      const { lines } = yield* captureLogs(
        Effect.log("issued session token", { token }).pipe(
          Effect.annotateLogs("token", token)
        )
      )

      assert.strictEqual(lines.length, 1)
      assert.notInclude(lines[0]!, raw)
      assert.include(lines[0]!, "<redacted>")
    }).pipe(Effect.provide(Token.layer)))

  it.effect("keeps the plaintext out of a rendered PasswordHashError", () =>
    Effect.gen(function*() {
      const hasher = yield* PasswordHasher.PasswordHasher
      const password = Redacted.make(plaintext)

      const cause = yield* Effect.flatMap(
        Effect.exit(hasher.verify(password, "this-is-not-a-hash")),
        (exit) => exit._tag === "Failure" ? Effect.succeed(exit.cause) : Effect.die("expected a failure")
      )

      const rendered = Cause.pretty(cause)
      assert.notInclude(rendered, plaintext)
      assert.notInclude(rendered, "correct")

      const failure = Cause.squash(cause) as PasswordHashError
      assert.strictEqual(failure._tag, "PasswordHashError")
      assert.notInclude(JSON.stringify(failure), plaintext)
      assert.notInclude(String(failure), plaintext)

      const { lines } = yield* captureLogs(Effect.logError("hash failed", failure))
      assert.strictEqual(lines.length, 1)
      assert.notInclude(lines[0]!, plaintext)
    }).pipe(Effect.provide(PasswordHasher.layerScrypt())))

  it.effect("keeps the plaintext out of a hash it produced", () =>
    Effect.gen(function*() {
      const hasher = yield* PasswordHasher.PasswordHasher
      const hash = yield* hasher.hash(Redacted.make(plaintext))

      assert.notInclude(hash, plaintext)
      assert.notInclude(hash, "correct")
    }).pipe(Effect.provide(PasswordHasher.layerScrypt({ N: 1024, r: 8 }))))
})
