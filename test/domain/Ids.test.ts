import { assert, describe, it } from "@effect/vitest"
import { Duration, Effect } from "effect"
import { TestClock } from "effect/testing"
import { isUuidV7, makeUnsafe, maxTimestampMillis, timestampOf, userId, uuidV7 } from "../../src/domain/Ids.js"

const zeroes = () => new Uint8Array(16)

describe("domain/Ids/makeUnsafe", () => {
  it("writes the version and variant bits and the big-endian timestamp", () => {
    const id = makeUnsafe(0x0189_abcd_ef01, zeroes())
    assert.strictEqual(isUuidV7(id), true)
    assert.strictEqual(id.slice(0, 8) + id.slice(9, 13), "0189abcdef01")
    // Version 7 in the high nibble of byte 6, RFC 9562 variant in byte 8.
    assert.strictEqual(id[14], "7")
    assert.ok("89ab".includes(id[19]!))
  })

  it("preserves every random bit it is not obliged to overwrite", () => {
    const bytes = new Uint8Array(16).fill(0xff)
    const id = makeUnsafe(0, bytes)
    // Bytes 0..5 are the timestamp; 6 and 8 are partly masked; the rest are
    // untouched randomness.
    assert.strictEqual(id.slice(24), "ffffffffffff")
    assert.strictEqual(bytes[6], 0x7f)
    assert.strictEqual(bytes[8], 0xbf)
  })

  it("clamps a timestamp that is out of range rather than producing a malformed id", () => {
    assert.strictEqual(timestampOf(makeUnsafe(-1, zeroes())), 0)
    assert.strictEqual(timestampOf(makeUnsafe(maxTimestampMillis + 1000, zeroes())), maxTimestampMillis)
    assert.strictEqual(isUuidV7(makeUnsafe(-1, zeroes())), true)
  })
})

describe("domain/Ids/isUuidV7", () => {
  it("rejects the shapes that are not one", () => {
    assert.strictEqual(isUuidV7("01890000-0000-7000-8000-00000000000a"), true)
    // Version 4, not 7.
    assert.strictEqual(isUuidV7("01890000-0000-4000-8000-00000000000a"), false)
    // Wrong variant nibble.
    assert.strictEqual(isUuidV7("01890000-0000-7000-c000-00000000000a"), false)
    // Uppercase is not the canonical form we write.
    assert.strictEqual(isUuidV7("01890000-0000-7000-8000-00000000000A"), false)
    assert.strictEqual(isUuidV7("not-a-uuid"), false)
    assert.strictEqual(isUuidV7(""), false)
  })
})

describe("domain/Ids/uuidV7", () => {
  it.effect("timestamps from the Effect clock, not the wall clock", () =>
    Effect.gen(function*() {
      // Under TestClock the epoch starts at zero, so a wall-clock
      // implementation would be off by decades.
      assert.strictEqual(timestampOf(yield* uuidV7), 0)

      yield* TestClock.adjust(Duration.hours(1))
      assert.strictEqual(timestampOf(yield* uuidV7), Duration.toMillis(Duration.hours(1)))
    }))

  it.effect("sorts lexicographically in mint order", () =>
    Effect.gen(function*() {
      // This is the whole reason for version 7: `ORDER BY id` is chronological,
      // and a primary-key index stays append-only.
      const first = yield* uuidV7
      yield* TestClock.adjust(Duration.millis(1))
      const second = yield* uuidV7
      yield* TestClock.adjust(Duration.seconds(30))
      const third = yield* uuidV7

      assert.ok(first < second)
      assert.ok(second < third)
      assert.deepStrictEqual([third, first, second].sort(), [first, second, third])
    }))

  it.effect("is unique within a single millisecond", () =>
    Effect.gen(function*() {
      const ids = new Set<string>()
      for (let i = 0; i < 256; i++) {
        const id = yield* uuidV7
        assert.strictEqual(isUuidV7(id), true)
        ids.add(id)
      }
      assert.strictEqual(ids.size, 256)
    }))

  it.effect("the branded constructors produce the same shape", () =>
    Effect.gen(function*() {
      assert.strictEqual(isUuidV7(yield* userId), true)
    }))
})
