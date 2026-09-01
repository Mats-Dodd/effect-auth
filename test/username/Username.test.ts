import { assert, describe, it, layer } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import { Passwords } from "../../src/domain/Passwords.js"
import { CredentialIssuer } from "../../src/domain/Schema.js"
import { AccountStore } from "../../src/domain/Stores.js"
import * as UsernameTest from "../../src/testing/UsernameTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import {
  defaults,
  makeConfig,
  normalizeUsername,
  refusalFor,
  reservedUsernames,
  Username
} from "../../src/username/index.js"
import type { UserId } from "../../src/domain/Schema.js"
import { expectSome, signUpUser, testPassword, uniqueEmail } from "../fixtures.js"

/** Removes a user's credential row, leaving an account with no way to prove a password. */
const dropCredential = Effect.fnUntraced(function* (userId: UserId) {
  const accounts = yield* AccountStore
  const credential = yield* expectSome(
    yield* accounts.findByIssuerAccountId(CredentialIssuer, userId),
    "expected a credential account"
  )
  assert.isTrue(yield* accounts.deleteById(credential.id, userId))
})

/** A name no other test in this file will take. */
let counter = 0
const uniqueName = (label: string) => `${label}-${(counter += 1)}-${globalThis.crypto.randomUUID().slice(0, 8)}`

describe("username/normalization", () => {
  it("case-folds, trims and normalizes to NFC", () => {
    assert.strictEqual(normalizeUsername("  Ada_Lovelace  "), "ada_lovelace")
    // The same name written with a combining acute and with a precomposed one
    // is one name, which is the whole of what NFC buys.
    assert.strictEqual(normalizeUsername("café"), normalizeUsername("café"))
  })

  it("does not compatibility-fold, so lookalikes stay distinct", () => {
    // NFKC would map this onto "ada". Collapsing confusables is UTS #39's job
    // and belongs in a soft signal, never in a unique index.
    assert.notStrictEqual(normalizeUsername("ａｄａ"), "ada")
  })
})

describe("username/validity", () => {
  const config = makeConfig()

  it("applies length in code points, not UTF-16 units", () => {
    assert.deepStrictEqual(refusalFor("ab", config), Option.some("too_short"))
    assert.deepStrictEqual(refusalFor("a".repeat(30), config), Option.none())
    assert.deepStrictEqual(refusalFor("a".repeat(31), config), Option.some("too_long"))
    // Two astral characters are two characters. Counted in UTF-16 units they
    // would be four, and a Unicode deployment's bound would silently halve.
    const unicode = makeConfig({ unicode: true, minLength: 2, maxLength: 2 })
    assert.deepStrictEqual(refusalFor("\u{1F600}\u{1F600}", unicode), Option.none())
  })

  it("refuses characters outside [a-z0-9_-] unless unicode is opted into", () => {
    assert.deepStrictEqual(refusalFor("ada.lovelace", config), Option.some("charset"))
    assert.deepStrictEqual(refusalFor("ada lovelace", config), Option.some("charset"))
    assert.deepStrictEqual(refusalFor("åda", config), Option.some("charset"))
    assert.deepStrictEqual(refusalFor("åda", makeConfig({ unicode: true })), Option.none())
  })

  it("refuses the structural characters whatever unicode says", () => {
    const unicode = makeConfig({ unicode: true })
    for (const candidate of ["ada/lovelace", "ada@lovelace", "ada?x", "ada#x", "ada%x", "ada lovelace"]) {
      assert.deepStrictEqual(refusalFor(candidate, unicode), Option.some("charset"), candidate)
    }
  })

  it("refuses control characters, and only control characters, in that range", () => {
    const unicode = makeConfig({ unicode: true })
    // The forbidden class names a control *range*. Written with literal bytes
    // it renders as an innocent space-to-at-sign range, which forbids every
    // digit and the hyphen — so these two are the pin: the shapes a real
    // username takes must survive it, whatever the class looks like.
    assert.deepStrictEqual(refusalFor("ada1", unicode), Option.none())
    assert.deepStrictEqual(refusalFor("ada-lovelace", unicode), Option.none())
    assert.deepStrictEqual(refusalFor("ada_lovelace", unicode), Option.none())
    assert.deepStrictEqual(refusalFor("0123456789", unicode), Option.none())

    // And the range itself still bites, at both ends and in the middle.
    for (const candidate of ["a\u0000b", "a\u001fb", "a\u007fb", "a\tb", "a\nb"]) {
      assert.deepStrictEqual(refusalFor(candidate, unicode), Option.some("charset"), JSON.stringify(candidate))
    }
  })

  it("refuses the shipped reserved list, case-insensitively", () => {
    assert.deepStrictEqual(refusalFor("admin", config), Option.some("reserved"))
    assert.deepStrictEqual(refusalFor("ADMIN", config), Option.some("reserved"))
    assert.deepStrictEqual(refusalFor("sign-in", config), Option.some("reserved"))
    assert.isTrue(reservedUsernames.has(".well-known"))
  })

  it("normalizes a deployment's own reserved list, so an unnormalized entry still bites", () => {
    const config = makeConfig({ reserved: ["Acme"] })
    assert.deepStrictEqual(refusalFor("acme", config), Option.some("reserved"))
    // It replaces rather than extends — spread `reservedUsernames` to keep it.
    assert.deepStrictEqual(refusalFor("admin", config), Option.none())
  })

  it("ships the documented defaults", () => {
    assert.strictEqual(defaults.minLength, 3)
    assert.strictEqual(defaults.maxLength, 30)
    assert.isFalse(defaults.unicode)
    assert.isFalse(defaults.availability)
  })
})

layer(UsernameTest.layer())("username/the service", (it) => {
  it.effect("stores the display form and resolves by any spelling of it", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("set"))
      const name = uniqueName("Ada")

      const record = yield* username.set({ userId: user.id, username: name })
      assert.strictEqual(record.username, name)
      assert.strictEqual(record.usernameKey, name.toLowerCase())

      const found = yield* expectSome(yield* username.find(name.toUpperCase()), "should resolve by any case")
      assert.strictEqual(found.userId, user.id)
      assert.deepStrictEqual(
        Option.map(yield* username.forUser(user.id), (row) => row.username),
        Option.some(name)
      )
    })
  )

  it.effect("releases the previous name when a person changes theirs", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("change"))
      const first = uniqueName("first")
      const second = uniqueName("second")

      yield* username.set({ userId: user.id, username: first })
      yield* username.set({ userId: user.id, username: second })

      assert.isTrue(Option.isNone(yield* username.find(first)))
      assert.deepStrictEqual(
        Option.map(yield* username.find(second), (row) => row.userId),
        Option.some(user.id)
      )
      // One row per person, not two: `user_id` is unique.
      assert.deepStrictEqual(
        Option.map(yield* username.forUser(user.id), (row) => row.username),
        Option.some(second)
      )
    })
  )

  it.effect("re-setting the same name keeps it and rewrites the display form", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("resame"))
      const name = uniqueName("ada")

      yield* username.set({ userId: user.id, username: name })
      const again = yield* username.set({ userId: user.id, username: name.toUpperCase() })
      assert.strictEqual(again.username, name.toUpperCase())
      assert.strictEqual(again.usernameKey, name.toLowerCase())
    })
  )

  it.effect("refuses a name somebody else holds, and leaves the loser's own name alone", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const holder = yield* signUpUser(uniqueEmail("holder"))
      const other = yield* signUpUser(uniqueEmail("other"))
      const wanted = uniqueName("wanted")
      const mine = uniqueName("mine")

      yield* username.set({ userId: holder.user.id, username: wanted })
      yield* username.set({ userId: other.user.id, username: mine })

      const failure = yield* Effect.flip(username.set({ userId: other.user.id, username: wanted }))
      assert.strictEqual(failure._tag, "UsernameTaken")

      // The release and the claim are one transaction, so a refused change is
      // not a lost name.
      assert.deepStrictEqual(
        Option.map(yield* username.forUser(other.user.id), (row) => row.username),
        Option.some(mine)
      )
      assert.deepStrictEqual(
        Option.map(yield* username.find(wanted), (row) => row.userId),
        Option.some(holder.user.id)
      )
    })
  )

  it.effect("enforces the rules on the write path, whatever the route did", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("invalid"))

      for (const [candidate, reason] of [
        ["ab", "too_short"],
        ["a".repeat(31), "too_long"],
        ["ada lovelace", "charset"],
        ["admin", "reserved"]
      ] as const) {
        const failure = yield* Effect.flip(username.set({ userId: user.id, username: candidate }))
        assert.strictEqual(failure._tag, "UsernameInvalid")
        assert.strictEqual(failure._tag === "UsernameInvalid" ? failure.reason : null, reason, candidate)
      }
      // Nothing was written on any of those paths.
      assert.isTrue(Option.isNone(yield* username.forUser(user.id)))
    })
  )

  it.effect("clear releases the name", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("clear"))
      const name = uniqueName("gone")

      yield* username.set({ userId: user.id, username: name })
      assert.isTrue(yield* username.clear(user.id))
      assert.isFalse(yield* username.clear(user.id))
      assert.isTrue(Option.isNone(yield* username.find(name)))
    })
  )

  it.effect("signs a person in and records the password as the evidence", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("signin"))
      const name = uniqueName("signin")
      yield* username.set({ userId: user.id, username: name })

      const result = yield* username.signIn({ username: name.toUpperCase(), password: testPassword })
      assert.strictEqual(result._tag, "Complete")
      if (result._tag !== "Complete") return
      assert.strictEqual(result.user.id, user.id)
      // The name is a lookup key; the factor proved is the password.
      assert.deepStrictEqual(
        result.session.methods.map((method) => method.method),
        ["password"]
      )
      assert.strictEqual(result.session.aal, "aal1")
    })
  )

  it.effect("refuses an unknown name, a wrong password and an account with no credential alike", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("refuse"))
      const name = uniqueName("refuse")
      yield* username.set({ userId: user.id, username: name })

      const unknown = yield* Effect.flip(username.signIn({ username: uniqueName("nobody"), password: testPassword }))
      assert.strictEqual(unknown._tag, "InvalidCredentials")

      const wrong = yield* Effect.flip(username.signIn({ username: name, password: Redacted.make("nope") }))
      assert.strictEqual(wrong._tag, "InvalidCredentials")

      yield* dropCredential(user.id)
      const credentialless = yield* Effect.flip(username.signIn({ username: name, password: testPassword }))
      assert.strictEqual(credentialless._tag, "InvalidCredentials")
    })
  )

  it.effect("answers availability against the rules as well as the rows", () =>
    Effect.gen(function* () {
      const username = yield* Username
      const { user } = yield* signUpUser(uniqueEmail("available"))
      const name = uniqueName("avail")

      assert.isTrue(yield* username.available(name))
      yield* username.set({ userId: user.id, username: name })
      assert.isFalse(yield* username.available(name))

      // A name nobody holds and nobody may have is not "available".
      const refused = yield* Effect.flip(username.available("admin"))
      assert.strictEqual(refused._tag, "UsernameInvalid")
    })
  )
})

describe.sequential("username/signIn (timing defence)", () => {
  // The counter belongs to the hashing layer, which is built once for this
  // block, so these assertions must not run beside a sibling's sign-in.
  const hasher = AuthTest.countingHasher()

  it.layer(UsernameTest.layer({ hasher: hasher.layer }))((it) => {
    it.effect("runs exactly one verification on every branch", () =>
      Effect.gen(function* () {
        const username = yield* Username
        const known = yield* signUpUser(uniqueEmail("timing-known"))
        const name = uniqueName("timing")
        yield* username.set({ userId: known.user.id, username: name })

        // Unknown name: the row lookup misses and the verification still runs,
        // against the dummy hash.
        const before = hasher.state.verifies
        assert.strictEqual(
          (yield* Effect.flip(username.signIn({ username: uniqueName("nobody"), password: testPassword })))._tag,
          "InvalidCredentials"
        )
        assert.strictEqual(hasher.state.verifies - before, 1)

        // Wrong password against a known name: one.
        const wrong = hasher.state.verifies
        assert.strictEqual(
          (yield* Effect.flip(username.signIn({ username: name, password: Redacted.make("nope") })))._tag,
          "InvalidCredentials"
        )
        assert.strictEqual(hasher.state.verifies - wrong, 1)

        // Right password: one.
        const right = hasher.state.verifies
        yield* username.signIn({ username: name, password: testPassword })
        assert.strictEqual(hasher.state.verifies - right, 1)

        // A name whose account has no credential at all — the branch
        // better-auth's equalisation misses — costs the same one.
        const other = yield* signUpUser(uniqueEmail("timing-oauth"))
        const orphan = uniqueName("orphan")
        yield* username.set({ userId: other.user.id, username: orphan })
        yield* dropCredential(other.user.id)
        const none = hasher.state.verifies
        assert.strictEqual(
          (yield* Effect.flip(username.signIn({ username: orphan, password: testPassword })))._tag,
          "InvalidCredentials"
        )
        assert.strictEqual(hasher.state.verifies - none, 1)
      })
    )
  })
})

describe.sequential("username/signIn (e-mail verification gate)", () => {
  it.layer(UsernameTest.layer({ emailPassword: { requireEmailVerification: true } }))((it) => {
    it.effect("refuses an unverified address only after the password verified", () =>
      Effect.gen(function* () {
        const username = yield* Username
        const passwords = yield* Passwords
        const { user } = yield* passwords.signUp({
          name: "Ada",
          email: uniqueEmail("gate"),
          password: testPassword
        })
        const name = uniqueName("gate")
        yield* username.set({ userId: user.id, username: name })

        const failure = yield* Effect.flip(username.signIn({ username: name, password: testPassword }))
        assert.strictEqual(failure._tag, "EmailNotVerified")

        // A wrong password on the same account is still InvalidCredentials: the
        // gate sits behind the verification, not in front of it, so it is never
        // an answer somebody guessing at a name can obtain.
        const wrong = yield* Effect.flip(username.signIn({ username: name, password: Redacted.make("nope") }))
        assert.strictEqual(wrong._tag, "InvalidCredentials")
      })
    )
  })
})
