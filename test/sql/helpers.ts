/**
 * The rows every suite under `test/sql/` starts from.
 *
 * **Details**
 *
 * `SqlStores`, `Errors`, `Concurrency` and `Dialect` all need the same four
 * things — a user, a session, an account, a verification — written through the
 * stores rather than through raw SQL, so that every dialect writes them the way
 * the library does. Keeping them here is what lets those four files assert
 * about behaviour instead of restating the insert.
 *
 * Nothing in this file names a dialect. A test that needs a dialect's own fact
 * says so through {@link Database.dialect}, in `Dialect.test.ts`.
 */
import { DateTime, Effect } from "effect"
import type { Duration } from "effect"
import type { AuthenticationMethod } from "../../src/domain/Assurance.js"
import { deriveAal } from "../../src/domain/Assurance.js"
import type { UserId } from "../../src/domain/Schema.js"
import { Account, CredentialIssuer, oauthIssuer, Session, User, Verification } from "../../src/domain/Schema.js"
import { AccountStore, SessionStore, UserStore, VerificationStore } from "../../src/domain/Stores.js"
import { testName } from "../fixtures.js"

/**
 * A value no other test in the process will write.
 *
 * A block shares one database, so a fixed `"hash-1"` in two tests is one row
 * that both of them find.
 *
 * A counter rather than a random suffix: a worker is one process, so a counter
 * is a stronger guarantee than randomness — and it keeps the fixture off the
 * global `crypto` this library's own code is not allowed to reach for.
 */
let uniqueCounter = 0
export const unique = (label: string): string => {
  uniqueCounter += 1
  return `${label}-${uniqueCounter}`
}

/** A user, through the store, so every dialect writes it the way the library does. */
export const createUser = Effect.fnUntraced(function* (email: string, emailVerified = false) {
  const users = yield* UserStore
  const row = yield* User.insert.makeEffect({
    name: testName,
    email,
    emailVerified,
    image: null
  })
  return yield* users.create(row)
})

/** A session for `userId`, expiring `ttl` from now. */
export const createSession = Effect.fnUntraced(function* (
  userId: UserId,
  tokenHash: string,
  ttl: Duration.Duration,
  rememberMe = true,
  methods: ReadonlyArray<AuthenticationMethod> = []
) {
  const sessions = yield* SessionStore
  const now = yield* DateTime.now
  const row = yield* Session.insert.makeEffect({
    tokenHash,
    userId,
    expiresAt: DateTime.addDuration(now, ttl),
    ipAddress: "203.0.113.7",
    userAgent: "vitest",
    rememberMe,
    methods,
    aal: deriveAal(methods)
  })
  return yield* sessions.create(row)
})

/** One entry of an authentication log, as a plugin states it. */
export const evidence = (
  name: string,
  factor: AuthenticationMethod["factor"],
  completedAt: DateTime.Utc
): AuthenticationMethod => ({
  method: name,
  completedAt,
  factor,
  phishingResistant: false,
  restricted: false
})

/** An OAuth sign-in method, identified by `providerId` and `accountId`. */
export const createOauthAccount = Effect.fnUntraced(function* (userId: UserId, providerId: string, accountId: string) {
  const accounts = yield* AccountStore
  return yield* accounts.create(
    yield* Account.insert.makeEffect({
      issuer: oauthIssuer(providerId),
      accountId,
      providerId,
      userId,
      accessToken: null,
      refreshToken: null,
      idToken: null,
      accessTokenExpiresAt: null,
      refreshTokenExpiresAt: null,
      scope: null,
      passwordHash: null
    })
  )
})

/** The password credential of `userId`. */
export const createCredentialAccount = Effect.fnUntraced(function* (userId: UserId, passwordHash: string) {
  const accounts = yield* AccountStore
  return yield* accounts.create(
    yield* Account.insert.makeEffect({
      issuer: CredentialIssuer,
      accountId: userId,
      providerId: "credential",
      userId,
      accessToken: null,
      refreshToken: null,
      idToken: null,
      accessTokenExpiresAt: null,
      refreshTokenExpiresAt: null,
      scope: null,
      passwordHash
    })
  )
})

/** A verification row under `identifier`, expiring `ttl` from now. */
export const createVerification = Effect.fnUntraced(function* (
  identifier: string,
  valueHash: string,
  ttl: Duration.Duration
) {
  const verifications = yield* VerificationStore
  const now = yield* DateTime.now
  const row = yield* Verification.insert.makeEffect({
    identifier,
    valueHash,
    payload: null,
    expiresAt: DateTime.addDuration(now, ttl)
  })
  return yield* verifications.create(row)
})
