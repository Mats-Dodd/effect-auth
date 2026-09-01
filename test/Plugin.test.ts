/**
 * The one helper a plugin outside this package cannot write for itself without
 * getting it subtly wrong.
 *
 * **Details**
 *
 * `withDefaults` is `{ ...defaults, ...overrides }` with the one behaviour that
 * spread does not have: a key present and explicitly `undefined` does not
 * overwrite a default. That is not a nicety — a partial options section built by
 * a caller who wrote `{ ttl: undefined }`, or produced by spreading their own
 * optional fields, has exactly those keys, and the naive spelling silently
 * erases every default they did not mention.
 *
 * Imported from the module rather than through `effect-auth`'s barrel: the
 * barrel is where a plugin reaches it (`Plugin.withDefaults`), and this file is
 * about the behaviour rather than the path.
 */
import { assert, describe, it } from "@effect/vitest"
import { Duration } from "effect"
import * as Plugin from "../src/Plugin.js"

interface OtpConfig {
  readonly ttl: Duration.Duration
  readonly digits: number
  readonly label: string | null
}

const defaults: OtpConfig = { ttl: Duration.minutes(10), digits: 8, label: null }

describe("Plugin", () => {
  it("answers the defaults when the section was left out entirely", () => {
    assert.deepStrictEqual(Plugin.withDefaults(defaults, undefined), defaults)
    assert.deepStrictEqual(Plugin.withDefaults(defaults, {}), defaults)
  })

  it("applies whatever the caller actually stated", () => {
    const resolved = Plugin.withDefaults(defaults, { digits: 6 })

    assert.strictEqual(resolved.digits, 6)
    assert.deepStrictEqual(resolved.ttl, Duration.minutes(10))
  })

  it("does not let an explicit undefined cost a default", () => {
    // The whole reason this is shared rather than rewritten per plugin.
    const resolved = Plugin.withDefaults(defaults, { digits: undefined, ttl: Duration.minutes(2) })

    assert.strictEqual(resolved.digits, 8)
    assert.deepStrictEqual(resolved.ttl, Duration.minutes(2))
  })

  it("keeps an explicit null, which is a value and not an absence", () => {
    const labelled: OtpConfig = { ...defaults, label: "otp" }
    const resolved = Plugin.withDefaults(labelled, { label: null })

    assert.isNull(resolved.label)
  })

  it("leaves the defaults it was handed untouched", () => {
    const before = { ...defaults }
    Plugin.withDefaults(defaults, { digits: 6 })

    assert.deepStrictEqual(defaults, before)
  })
})
