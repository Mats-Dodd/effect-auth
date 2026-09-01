import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AccountStore } from "../../src/domain/Stores.js"
import { OneTap } from "../../src/one-tap/index.js"
import * as OneTapTest from "../../src/testing/OneTapTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { uniqueEmail } from "../fixtures.js"

/** The failure tag of an effect that is expected to fail. */
const failureTag = <A, E extends { readonly _tag: string }, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.map(Effect.result(effect), (result) => (result._tag === "Failure" ? result.failure._tag : "Success"))

let counter = 0
const uniqueSubject = (): string => `google-subject-${counter++}`

describe.sequential("one-tap/OneTap", () => {
  layer(OneTapTest.layer())("a credential this browser asked for", (it) => {
    it.effect("signs the person in and provisions the account", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const email = uniqueEmail("one-tap")
        const subject = uniqueSubject()
        const { nonce } = yield* oneTap.mintNonce

        const result = yield* oneTap.callback({
          credential: yield* OneTapTest.credential({ subject, email, nonce }),
          expectedNonce: nonce
        })

        assert.strictEqual(result._tag, "Complete")
        if (result._tag !== "Complete") return
        assert.strictEqual(result.user.email, email)
        assert.isTrue(result.user.emailVerified)
      })
    )

    it.effect("records the same evidence the redirect flow does", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const result = yield* oneTap.callback({
          credential: yield* OneTapTest.credential({
            subject: uniqueSubject(),
            email: uniqueEmail("evidence"),
            nonce
          }),
          expectedNonce: nonce
        })

        assert.strictEqual(result._tag, "Complete")
        if (result._tag !== "Complete") return
        assert.deepStrictEqual(
          result.session.methods.map((method) => ({
            method: method.method,
            factor: method.factor,
            phishingResistant: method.phishingResistant,
            restricted: method.restricted
          })),
          [{ method: "oauth:google", factor: "possession", phishingResistant: false, restricted: false }]
        )
        // A federated sign-in is one factor, whatever happened at the provider.
        assert.strictEqual(result.session.aal, "aal1")
      })
    )

    it.effect("stores no provider tokens, because a One Tap credential is not a grant", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const accounts = yield* AccountStore
        const subject = uniqueSubject()
        const { nonce } = yield* oneTap.mintNonce

        yield* oneTap.callback({
          credential: yield* OneTapTest.credential({ subject, email: uniqueEmail("no-tokens"), nonce }),
          expectedNonce: nonce
        })

        const account = yield* accounts.findByIssuerAccountId(OneTapTest.testIssuer, subject)
        assert.isTrue(Option.isSome(account))
        if (Option.isNone(account)) return
        assert.isNull(account.value.accessToken)
        assert.isNull(account.value.refreshToken)
      })
    )

    it.effect("the subject is the identity: a second credential with a new address is the same account", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const subject = uniqueSubject()

        const first = yield* Effect.flatMap(oneTap.mintNonce, ({ nonce }) =>
          Effect.flatMap(OneTapTest.credential({ subject, email: uniqueEmail("sub-wins-a"), nonce }), (credential) =>
            oneTap.callback({ credential, expectedNonce: nonce })
          )
        )
        const second = yield* Effect.flatMap(oneTap.mintNonce, ({ nonce }) =>
          Effect.flatMap(OneTapTest.credential({ subject, email: uniqueEmail("sub-wins-b"), nonce }), (credential) =>
            oneTap.callback({ credential, expectedNonce: nonce })
          )
        )

        assert.strictEqual(first._tag, "Complete")
        assert.strictEqual(second._tag, "Complete")
        if (first._tag !== "Complete" || second._tag !== "Complete") return
        assert.strictEqual(first.user.id, second.user.id)
      })
    )

    it.effect("mints a different nonce every time", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const first = yield* oneTap.mintNonce
        const second = yield* oneTap.mintNonce
        assert.notStrictEqual(first.nonce, second.nonce)
        assert.isAtLeast(first.nonce.length, 32)
      })
    )
  })

  layer(OneTapTest.layer())("the nonce binding", (it) => {
    it.effect("refuses a credential carrying no nonce at all", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("no-nonce")
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("refuses a credential minted for another browser's nonce", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const mine = yield* oneTap.mintNonce
        const theirs = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("replay"),
          nonce: theirs.nonce
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: mine.nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("refuses a request that presented no nonce cookie", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("no-cookie"),
          nonce
        })
        assert.strictEqual(yield* failureTag(oneTap.callback({ credential })), "OneTapRejected")
      })
    )

    it.effect("refuses a page whose own copy disagrees with the cookie", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("disagree"),
          nonce
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce, nonce: "something-else" })),
          "OneTapRejected"
        )
      })
    )
  })

  layer(OneTapTest.layer({ oneTap: { requireNonce: false } }))("with the nonce requirement switched off", (it) => {
    it.effect("accepts a credential that carries none", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const result = yield* oneTap.callback({
          credential: yield* OneTapTest.credential({
            subject: uniqueSubject(),
            email: uniqueEmail("nonce-off")
          })
        })
        assert.strictEqual(result._tag, "Complete")
      })
    )
  })

  layer(OneTapTest.layer())("the token itself", (it) => {
    it.effect("refuses a token minted for another Google application", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("audience"),
          nonce,
          audience: "somebody-elses.apps.googleusercontent.com"
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("refuses a token from an issuer that is not Google", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("issuer"),
          nonce,
          issuer: "https://accounts.evil.example"
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("accepts both spellings of Google's own issuer", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        for (const issuer of ["accounts.google.com", "https://accounts.google.com"]) {
          const { nonce } = yield* oneTap.mintNonce
          const credential = yield* OneTapTest.credential({
            subject: uniqueSubject(),
            email: uniqueEmail("issuers"),
            nonce,
            issuer
          })
          const result = yield* oneTap.callback({ credential, expectedNonce: nonce })
          assert.strictEqual(result._tag, "Complete")
        }
      })
    )

    it.effect("refuses a token whose signature has been tampered with", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("forged"),
          nonce
        })
        const raw = Redacted.value(credential)
        const tampered = Redacted.make(`${raw.slice(0, -2)}${raw.endsWith("A") ? "B" : "A"}`)
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential: tampered, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("refuses a token whose exp has passed", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const oneTap = yield* OneTap
          const { nonce } = yield* oneTap.mintNonce
          const credential = yield* OneTapTest.credential({
            subject: uniqueSubject(),
            email: uniqueEmail("expired"),
            nonce,
            expiresIn: 60
          })
          yield* TestClock.adjust(Duration.minutes(5))
          assert.strictEqual(
            yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
            "OAuthProviderError"
          )
        })
      )
    )

    it.effect("refuses a token with no expiry at all", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("no-exp"),
          nonce,
          expiresIn: null
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )
  })

  layer(OneTapTest.layer({ provider: { hostedDomain: "example.com" } }))("the hosted-domain restriction", (it) => {
    it.effect("is the provider's own rule, applied to a One Tap credential", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: "ada@other.example",
          nonce,
          hostedDomain: "other.example"
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )

    it.effect("admits an account inside the domain", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("workspace"),
          nonce,
          hostedDomain: "example.com"
        })
        const result = yield* oneTap.callback({ credential, expectedNonce: nonce })
        assert.strictEqual(result._tag, "Complete")
      })
    )

    it.effect("refuses a credential that claims no domain at all", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("no-hd"),
          nonce
        })
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })),
          "OAuthProviderError"
        )
      })
    )
  })

  layer(OneTapTest.layer({ oneTap: { uxMode: "redirect" } }))("redirect mode", (it) => {
    it.effect("requires the g_csrf_token body field to match its cookie", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("csrf"),
          nonce
        })

        assert.strictEqual(yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce })), "OneTapRejected")
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce, csrfToken: "a", csrfCookie: "b" })),
          "OneTapRejected"
        )
        assert.strictEqual(
          yield* failureTag(oneTap.callback({ credential, expectedNonce: nonce, csrfToken: "a" })),
          "OneTapRejected"
        )
      })
    )

    it.effect("accepts one that does", () =>
      Effect.gen(function* () {
        const oneTap = yield* OneTap
        const { nonce } = yield* oneTap.mintNonce
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("csrf-ok"),
          nonce
        })
        const result = yield* oneTap.callback({
          credential,
          expectedNonce: nonce,
          csrfToken: "a-matching-token",
          csrfCookie: "a-matching-token"
        })
        assert.strictEqual(result._tag, "Complete")
      })
    )
  })
})
