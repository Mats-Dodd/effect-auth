/**
 * The four stores, on whichever database `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * Nothing in this file knows which dialect it is running on: every row is
 * written and read through a store, so a value that a dialect spells
 * differently — a boolean, a timestamp — is decoded before an assertion ever
 * sees it. The facts that are deliberately different live in `Dialect.test.ts`;
 * the failures the stores classify live in `Errors.test.ts`; the races live in
 * `Concurrency.test.ts`.
 */
import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { deriveAal } from "../../src/domain/Assurance.js"
import { Account, CredentialIssuer, oauthIssuer, Session, UserId } from "../../src/domain/Schema.js"
import {
  AccountStore,
  SessionStore,
  UserStore,
  VerificationStore,
  WithAuthTransaction
} from "../../src/domain/Stores.js"
import * as Database from "../../src/testing/Database.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, uniqueEmail } from "../fixtures.js"
import { createSession, createUser, createVerification, evidence, unique } from "./helpers.js"

layer(AuthTest.layerStores)("sql/SqlStores", (it) => {
  // ---------------------------------------------------------------------------
  // UserStore
  // ---------------------------------------------------------------------------

  describe("UserStore", () => {
    it.effect("creates, reads, updates and deletes a user", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const email = uniqueEmail("crud")
        const created = yield* createUser(email)

        assert.strictEqual(created.email, email)
        assert.strictEqual(created.emailVerified, false)
        assert.strictEqual(created.image, null)
        assert.strictEqual(DateTime.isUtc(created.createdAt), true)

        const byId = yield* expectSome(yield* users.findById(created.id), "expected the user by id")
        assert.strictEqual(byId.id, created.id)

        const byEmail = yield* expectSome(yield* users.findByEmail(email), "expected the user by e-mail")
        assert.strictEqual(byEmail.id, created.id)

        const updated = yield* expectSome(
          yield* users.update(created.id, { name: "Ada L.", emailVerified: true, image: null }),
          "expected the updated user"
        )
        assert.strictEqual(updated.name, "Ada L.")
        assert.strictEqual(updated.emailVerified, true)

        assert.strictEqual(yield* users.delete(created.id), true)
        assert.strictEqual(yield* users.delete(created.id), false)
        assert.strictEqual(Option.isNone(yield* users.findById(created.id)), true)
      })
    )

    it.effect("returns None for an unknown user", () =>
      Effect.gen(function* () {
        const users = yield* UserStore

        assert.strictEqual(Option.isNone(yield* users.findByEmail(uniqueEmail("nobody"))), true)
        assert.strictEqual(Option.isNone(yield* users.update(UserId.make("missing"), { name: "x" })), true)
      })
    )

    it.effect("locks a user row inside a transaction, and tolerates an unknown id", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const transaction = yield* WithAuthTransaction
        const created = yield* createUser(uniqueEmail("lock"))

        // It answers nothing — it is taken for the lock, not the row — and must
        // not throw when the id matches no row (`FOR UPDATE` of an empty result
        // is a no-op, and the SQLite degrade is a plain read).
        yield* transaction.run(
          Effect.gen(function* () {
            yield* users.lockUserRow(created.id)
            yield* users.lockUserRow(UserId.make("missing"))
          })
        )
      })
    )
  })

  // ---------------------------------------------------------------------------
  // SessionStore
  // ---------------------------------------------------------------------------

  describe("SessionStore", () => {
    it.effect("resolves a token hash to the session and its user in one read", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const email = uniqueEmail("session")
        const hash = unique("hash-join")
        const user = yield* createUser(email, true)
        const session = yield* createSession(user.id, hash, Duration.days(7))

        const found = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the joined row")

        assert.strictEqual(found.session.id, session.id)
        assert.strictEqual(found.session.tokenHash, hash)
        assert.strictEqual(found.session.ipAddress, "203.0.113.7")
        assert.strictEqual(found.user.id, user.id)
        assert.strictEqual(found.user.email, email)
        assert.strictEqual(found.user.emailVerified, true)
        assert.strictEqual(DateTime.toEpochMillis(found.session.expiresAt), DateTime.toEpochMillis(session.expiresAt))

        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(unique("nope"))), true)
      })
    )

    it.effect("extends a session with touch", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-touch")
        const user = yield* createUser(uniqueEmail("touch"))
        const session = yield* createSession(user.id, hash, Duration.days(1))
        const now = yield* DateTime.now
        const later = DateTime.addDuration(now, Duration.days(30))

        const touched = yield* expectSome(yield* sessions.touch(session.id, later), "expected the touched session")
        assert.strictEqual(DateTime.toEpochMillis(touched.expiresAt), DateTime.toEpochMillis(later))

        const reread = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the session")
        assert.strictEqual(DateTime.toEpochMillis(reread.session.expiresAt), DateTime.toEpochMillis(later))
      })
    )

    it.effect("persists remember_me and reads it back on the joined row", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const rememberedHash = unique("hash-remembered")
        const forgottenHash = unique("hash-forgotten")
        const user = yield* createUser(uniqueEmail("remember"))

        const remembered = yield* createSession(user.id, rememberedHash, Duration.days(7), true)
        const forgotten = yield* createSession(user.id, forgottenHash, Duration.days(1), false)

        // The flag survives the insert round-trip on the returned row …
        assert.strictEqual(remembered.rememberMe, true)
        assert.strictEqual(forgotten.rememberMe, false)

        // … and the joined read the hot path uses.
        const foundRemembered = yield* expectSome(
          yield* sessions.findByTokenHash(rememberedHash),
          "expected the remembered session"
        )
        const foundForgotten = yield* expectSome(
          yield* sessions.findByTokenHash(forgottenHash),
          "expected the forgotten session"
        )
        assert.strictEqual(foundRemembered.session.rememberMe, true)
        assert.strictEqual(foundForgotten.session.rememberMe, false)
      })
    )

    it.effect("leaves remember_me untouched across a rolling refresh", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-remember-touch")
        const user = yield* createUser(uniqueEmail("remember-touch"))
        const session = yield* createSession(user.id, hash, Duration.days(1), false)
        const now = yield* DateTime.now

        const touched = yield* expectSome(
          yield* sessions.touch(session.id, DateTime.addDuration(now, Duration.hours(1))),
          "expected the touched session"
        )
        // Touch moves only the expiry; a short session must not be promoted.
        assert.strictEqual(touched.rememberMe, false)

        const listed = yield* sessions.listByUserId(user.id)
        const reread = listed.find((row) => row.tokenHash === hash)
        assert.strictEqual(reread?.rememberMe, false)
      })
    )

    it.effect("stores the authentication log, the level and the stamp, and reads them back on the joined row", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-assurance")
        const user = yield* createUser(uniqueEmail("assurance"))
        const now = yield* DateTime.now
        const log = [evidence("password", "knowledge", now), evidence("totp", "possession", now)]

        const created = yield* createSession(user.id, hash, Duration.days(7), true, log)

        assert.deepStrictEqual(created.methods, log)
        assert.strictEqual(created.aal, "aal2")

        // The joined read is the hot path: a column it forgets is a column the
        // request-authentication path silently cannot see.
        const found = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the joined row")
        assert.deepStrictEqual(found.session.methods, log)
        assert.strictEqual(found.session.aal, "aal2")
        assert.strictEqual(
          DateTime.toEpochMillis(found.session.authenticatedAt),
          DateTime.toEpochMillis(created.authenticatedAt)
        )
      })
    )

    it.effect("defaults an unstated log to nothing at aal1, stamped with the insert clock", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-assurance-default")
        const user = yield* createUser(uniqueEmail("assurance-default"))
        const now = yield* DateTime.now

        // Deliberately stating none of the three: a writer that predates
        // step-up gets the row every session had before this wave — one
        // ordinary authenticated session, authenticated now.
        const created = yield* sessions.create(
          yield* Session.insert.makeEffect({
            tokenHash: hash,
            userId: user.id,
            expiresAt: DateTime.addDuration(now, Duration.days(1)),
            ipAddress: null,
            userAgent: null,
            rememberMe: true
          })
        )

        assert.deepStrictEqual(created.methods, [])
        assert.strictEqual(created.aal, "aal1")
        assert.strictEqual(DateTime.toEpochMillis(created.authenticatedAt), DateTime.toEpochMillis(created.createdAt))
      })
    )

    it.effect("elevates a session in one statement: the log, the level, the stamp and a new token", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-elevate")
        const rotated = unique("hash-elevated")
        const user = yield* createUser(uniqueEmail("elevate"))
        const now = yield* DateTime.now
        const first = evidence("password", "knowledge", now)
        const created = yield* createSession(user.id, hash, Duration.days(7), true, [first])

        assert.strictEqual(created.aal, "aal1")

        const second = evidence("totp", "possession", DateTime.addDuration(now, Duration.minutes(3)))
        const methods = [first, second]
        const elevated = yield* expectSome(
          yield* sessions.elevate(created.id, {
            append: (stored) => {
              // The log handed to `append` is the row's own, not anything the
              // caller was holding.
              assert.deepStrictEqual(stored, [first])
              return { methods, aal: deriveAal(methods) }
            },
            authenticatedAt: DateTime.addDuration(now, Duration.minutes(3)),
            tokenHash: rotated
          }),
          "expected the elevated session"
        )

        // The id survives, so open tabs and the session list do.
        assert.strictEqual(elevated.id, created.id)
        assert.deepStrictEqual(elevated.methods, methods)
        assert.strictEqual(elevated.aal, "aal2")
        assert.strictEqual(elevated.tokenHash, rotated)
        assert.strictEqual(
          DateTime.toEpochMillis(elevated.authenticatedAt),
          DateTime.toEpochMillis(DateTime.addDuration(now, Duration.minutes(3)))
        )

        // The token is replaced, not added to: one captured at aal1 must not
        // inherit the level the session has now.
        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(hash)), true)
        const found = yield* expectSome(yield* sessions.findByTokenHash(rotated), "expected the elevated session")
        assert.strictEqual(found.session.aal, "aal2")
        assert.deepStrictEqual(found.session.methods, methods)
      })
    )

    it.effect("answers None rather than inventing a row when the session is already gone", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-elevate-gone")
        const user = yield* createUser(uniqueEmail("elevate-gone"))
        const now = yield* DateTime.now
        const session = yield* createSession(user.id, hash, Duration.days(1))

        assert.strictEqual(yield* sessions.deleteById(session.id, user.id), true)

        let appended = false
        const answered = yield* sessions.elevate(session.id, {
          append: (stored) => {
            appended = true
            return { methods: stored, aal: "aal1" }
          },
          authenticatedAt: now,
          tokenHash: unique("hash-elevate-gone-new")
        })

        // `None`, the shape `touch` uses for exactly this — and the merge was
        // never run, so a caller's `append` cannot have side effects on a row
        // that is not there.
        assert.strictEqual(Option.isNone(answered), true)
        assert.isFalse(appended)
      })
    )

    it.effect("appends to the stored log, not to the one a stale caller is holding", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-elevate-stale")
        const user = yield* createUser(uniqueEmail("elevate-stale"))
        const now = yield* DateTime.now
        const password = evidence("password", "knowledge", now)
        const created = yield* createSession(user.id, hash, Duration.days(7), true, [])

        // Somebody else raised it first — a `reauthenticate`, or a parallel
        // request — while our caller was still holding the empty log it read.
        yield* expectSome(
          yield* sessions.elevate(created.id, {
            append: () => ({ methods: [password], aal: "aal1" }),
            authenticatedAt: now,
            tokenHash: unique("hash-elevate-stale-1")
          }),
          "expected the first elevation"
        )

        const totp = evidence("totp", "possession", now)
        const elevated = yield* expectSome(
          yield* sessions.elevate(created.id, {
            append: (stored) => {
              const methods = [...stored, totp]
              return { methods, aal: deriveAal(methods) }
            },
            authenticatedAt: now,
            tokenHash: unique("hash-elevate-stale-2")
          }),
          "expected the second elevation"
        )

        // Both entries survive, so the level is right. Reading the caller's own
        // `methods` instead would have written `[totp]` and stayed at aal1 —
        // the password the session really proved, silently dropped.
        assert.deepStrictEqual(elevated.methods, [password, totp])
        assert.strictEqual(elevated.aal, "aal2")
      })
    )

    it.effect("leaves the authentication stamp untouched across a rolling refresh", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-stamp-touch")
        const user = yield* createUser(uniqueEmail("stamp-touch"))
        const now = yield* DateTime.now
        const session = yield* createSession(user.id, hash, Duration.days(1))

        yield* expectSome(
          yield* sessions.touch(session.id, DateTime.addDuration(now, Duration.days(30))),
          "expected the touched session"
        )

        // Browsing must not keep a sensitive operation authorized for ever:
        // the refresh moves the expiry and nothing about the assurance.
        const found = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the session")
        assert.strictEqual(
          DateTime.toEpochMillis(found.session.authenticatedAt),
          DateTime.toEpochMillis(session.authenticatedAt)
        )
        assert.strictEqual(found.session.aal, session.aal)
        assert.deepStrictEqual(found.session.methods, session.methods)
      })
    )

    it.effect("scopes deleteById to the owning user", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const hash = unique("hash-owned")
        const owner = yield* createUser(uniqueEmail("owner"))
        const other = yield* createUser(uniqueEmail("other"))
        const session = yield* createSession(owner.id, hash, Duration.days(1))

        assert.strictEqual(yield* sessions.deleteById(session.id, other.id), false)
        assert.strictEqual(Option.isSome(yield* sessions.findByTokenHash(hash)), true)

        assert.strictEqual(yield* sessions.deleteById(session.id, owner.id), true)
        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(hash)), true)
      })
    )
  })

  // ---------------------------------------------------------------------------
  // AccountStore
  // ---------------------------------------------------------------------------

  describe("AccountStore", () => {
    it.effect("creates and reads accounts by both identities", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("accounts"))
        const accountId = unique("gh")

        const credential = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: CredentialIssuer,
            accountId: user.id,
            providerId: "credential",
            userId: user.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: "scrypt$n=16384,r=16,p=1$c2FsdA$a2V5"
          })
        )

        assert.strictEqual(credential.passwordHash, "scrypt$n=16384,r=16,p=1$c2FsdA$a2V5")

        const oauth = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId,
            providerId: "github",
            userId: user.id,
            accessToken: "gho_secret",
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: "read:user",
            passwordHash: null
          })
        )

        const sql = yield* SqlClient.SqlClient
        const raw = yield* sql<{
          readonly access_token: string
        }>`SELECT access_token FROM accounts WHERE id = ${oauth.id}`
        assert.strictEqual(raw.length, 1)
        assert.notStrictEqual(raw[0]!.access_token, "gho_secret")
        assert.isTrue(raw[0]!.access_token.startsWith("v1."))

        const byIssuer = yield* expectSome(
          yield* accounts.findByIssuerAccountId(oauthIssuer("github"), accountId),
          "expected the github account"
        )
        assert.strictEqual(byIssuer.providerId, "github")
        assert.strictEqual(byIssuer.accessToken, "gho_secret")

        const byProvider = yield* expectSome(
          yield* accounts.findByUserIdAndProviderId(user.id, "credential"),
          "expected the credential account"
        )
        assert.strictEqual(byProvider.id, credential.id)

        const byId = yield* expectSome(
          yield* accounts.findByIdAndUserId(byIssuer.id, user.id),
          "expected the github account by its own id"
        )
        assert.strictEqual(byId.id, byIssuer.id)

        // Ownership is a predicate of the statement, not a check afterwards: a
        // real account belonging to somebody else answers exactly as a
        // non-existent one does.
        const stranger = yield* createUser(uniqueEmail("accounts-stranger"))
        assert.isTrue(Option.isNone(yield* accounts.findByIdAndUserId(byIssuer.id, stranger.id)))

        assert.strictEqual(yield* accounts.countByUserId(user.id), 2)
        assert.strictEqual((yield* accounts.listByUserId(user.id)).length, 2)

        // The locking read answers the same rows; the lock it takes is what
        // makes `Accounts.unlink`'s last-method guard race-safe.
        const locked = yield* accounts.listByUserIdForUpdate(user.id)
        assert.deepStrictEqual(
          locked.map((account) => account.id),
          (yield* accounts.listByUserId(user.id)).map((account) => account.id)
        )
      })
    )

    it.effect("updates tokens and the credential password hash", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("tokens"))
        const now = yield* DateTime.now
        const expiry = DateTime.addDuration(now, Duration.hours(1))

        const account = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId: unique("gh"),
            providerId: "github",
            userId: user.id,
            accessToken: "old",
            refreshToken: "refresh",
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: null
          })
        )

        const updated = yield* expectSome(
          yield* accounts.updateTokens(account.id, {
            accessToken: "new",
            accessTokenExpiresAt: expiry,
            scope: "read:user"
          }),
          "expected the updated account"
        )

        assert.strictEqual(updated.accessToken, "new")
        // absent keys are left untouched
        assert.strictEqual(updated.refreshToken, "refresh")
        assert.strictEqual(updated.scope, "read:user")
        assert.strictEqual(
          updated.accessTokenExpiresAt === null ? null : DateTime.toEpochMillis(updated.accessTokenExpiresAt),
          DateTime.toEpochMillis(expiry)
        )

        // no local:credential account yet
        assert.strictEqual(Option.isNone(yield* accounts.updatePasswordHash(user.id, "pbkdf2$i=600000$s$k")), true)

        yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: CredentialIssuer,
            accountId: user.id,
            providerId: "credential",
            userId: user.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: "old-hash"
          })
        )

        const rehashed = yield* expectSome(
          yield* accounts.updatePasswordHash(user.id, "pbkdf2$i=600000$s$k"),
          "expected the credential account"
        )
        assert.strictEqual(rehashed.passwordHash, "pbkdf2$i=600000$s$k")
      })
    )

    it.effect("scopes deleteById to the owning user", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const owner = yield* createUser(uniqueEmail("acc-owner"))
        const other = yield* createUser(uniqueEmail("acc-other"))

        const account = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId: unique("gh"),
            providerId: "github",
            userId: owner.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: null
          })
        )

        assert.strictEqual(yield* accounts.deleteById(account.id, other.id), false)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 1)

        assert.strictEqual(yield* accounts.deleteById(account.id, owner.id), true)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 0)
      })
    )

    it.effect("deletes every method of one user, and only that user's", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const owner = yield* createUser(uniqueEmail("acc-purge-owner"))
        const other = yield* createUser(uniqueEmail("acc-purge-other"))

        const link = (userId: typeof owner.id, providerId: string) =>
          Effect.flatMap(
            Account.insert.makeEffect({
              issuer: oauthIssuer(providerId),
              accountId: unique(providerId),
              providerId,
              userId,
              accessToken: null,
              refreshToken: null,
              idToken: null,
              accessTokenExpiresAt: null,
              refreshTokenExpiresAt: null,
              scope: null,
              passwordHash: null
            }),
            (row) => accounts.create(row)
          )

        yield* link(owner.id, "github")
        yield* link(owner.id, "google")
        yield* link(other.id, "github")

        assert.strictEqual(yield* accounts.deleteByUserId(owner.id), 2)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 0)
        // The neighbour's row is untouched: the statement is scoped by user.
        assert.strictEqual(yield* accounts.countByUserId(other.id), 1)

        // And a user with nothing linked is not an error.
        assert.strictEqual(yield* accounts.deleteByUserId(owner.id), 0)
      })
    )
  })

  // ---------------------------------------------------------------------------
  // VerificationStore
  // ---------------------------------------------------------------------------

  describe("VerificationStore", () => {
    it.effect("consumes a value exactly once", () =>
      Effect.gen(function* () {
        const verifications = yield* VerificationStore
        const identifier = unique("email-verify")
        yield* createVerification(identifier, "value-hash", Duration.hours(1))

        const first = yield* verifications.consume(identifier, "value-hash")
        assert.strictEqual(Option.isSome(first), true)

        const second = yield* verifications.consume(identifier, "value-hash")
        assert.strictEqual(Option.isNone(second), true)
      })
    )

    it.effect("deletes every row under one identifier, expired or not", () =>
      Effect.gen(function* () {
        const verifications = yield* VerificationStore
        // Two reset links for the same user, plus somebody else's row, which
        // must survive.
        const ada = unique("password-reset-ada")
        const bob = unique("password-reset-bob")
        yield* createVerification(ada, "first-hash", Duration.hours(1))
        yield* createVerification(ada, "second-hash", Duration.hours(1))
        yield* createVerification(bob, "bobs-hash", Duration.hours(1))

        assert.strictEqual(yield* verifications.deleteByIdentifier(ada), 2)
        assert.strictEqual(Option.isNone(yield* verifications.consume(ada, "first-hash")), true)
        assert.strictEqual(Option.isSome(yield* verifications.consume(bob, "bobs-hash")), true)
        // An identifier with nothing under it is not an error.
        assert.strictEqual(yield* verifications.deleteByIdentifier(ada), 0)
      })
    )
  })

  // ---------------------------------------------------------------------------
  // WithAuthTransaction
  // ---------------------------------------------------------------------------

  describe("WithAuthTransaction", () => {
    it.effect("commits every write of a successful effect", () =>
      Effect.gen(function* () {
        const transaction = yield* WithAuthTransaction
        const users = yield* UserStore

        const user = yield* transaction.run(
          Effect.gen(function* () {
            const user = yield* createUser(uniqueEmail("tx-ok"))
            yield* createSession(user.id, unique("hash-tx"), Duration.days(1))
            return user
          })
        )

        assert.strictEqual(Option.isSome(yield* users.findById(user.id)), true)
      })
    )
  })
})

// -----------------------------------------------------------------------------
// The table-wide operations, on a database of their own
// -----------------------------------------------------------------------------

/**
 * These two sweep whole tables.
 *
 * `deleteExpired` counts every row any sibling happens to have written, so each
 * case starts from an empty database — `TestDatabase.reset`, which empties the
 * tables and leaves the migration bookkeeping alone, rather than a `layer()`
 * block per case booting a database of its own.
 *
 * `describe.sequential` is what makes that safe: tests in a block otherwise run
 * concurrently, and one case's reset would empty the table another was counting.
 */
layer(AuthTest.layerStores)("sql/SqlStores (whole-table)", (it) => {
  describe.sequential("whole-table", () => {
    it.effect("lists, revokes and expires sessions", () =>
      Effect.gen(function* () {
        yield* Effect.flatMap(Database.TestDatabase, (database) => database.reset)
        const sessions = yield* SessionStore
        const user = yield* createUser(uniqueEmail("many"))
        const first = yield* createSession(user.id, "hash-1", Duration.days(7))
        yield* createSession(user.id, "hash-2", Duration.days(7))
        yield* createSession(user.id, "hash-3", Duration.minutes(-1))

        const live = yield* sessions.listByUserId(user.id)
        assert.deepStrictEqual(live.map((session) => session.tokenHash).sort(), ["hash-1", "hash-2"])

        assert.strictEqual(yield* sessions.deleteExpired, 1)

        assert.strictEqual(yield* sessions.deleteByUserIdExcept(user.id, first.id), 1)
        assert.deepStrictEqual(
          (yield* sessions.listByUserId(user.id)).map((session) => session.tokenHash),
          ["hash-1"]
        )

        assert.strictEqual(yield* sessions.deleteByUserId(user.id), 1)
        assert.deepStrictEqual(yield* sessions.listByUserId(user.id), [])
      })
    )

    it.effect("refuses an expired row and a wrong value hash", () =>
      Effect.gen(function* () {
        yield* Effect.flatMap(Database.TestDatabase, (database) => database.reset)
        const verifications = yield* VerificationStore
        yield* createVerification("oauth-state:expired", "expired-hash", Duration.minutes(-1))
        yield* createVerification("oauth-state:live", "live-hash", Duration.minutes(10))

        assert.strictEqual(Option.isNone(yield* verifications.consume("oauth-state:expired", "expired-hash")), true)
        assert.strictEqual(Option.isNone(yield* verifications.consume("oauth-state:live", "wrong-hash")), true)
        assert.strictEqual(Option.isSome(yield* verifications.consume("oauth-state:live", "live-hash")), true)

        // the expired row is still there until it is swept
        assert.strictEqual(yield* verifications.deleteExpired, 1)
        assert.strictEqual(yield* verifications.deleteExpired, 0)
      })
    )
  })
})
