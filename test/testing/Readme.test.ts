/**
 * The README's Testing section is prose about a module, and prose drifts: it
 * told readers to pass `AuthTest.testTimeout` for a while after nothing of that
 * name existed, and a consumer copying the snippet got a type error on their
 * first test. So every name the README reaches through one of the testing
 * namespaces is checked against what that namespace actually exports.
 */
import { assert, describe, it } from "@effect/vitest"
// oxlint-disable-next-line effecttsgo/node-builtin-import -- a doc gate has to read the doc
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import * as Testing from "../../src/testing/index.js"

const readme = (): string => readFileSync(fileURLToPath(new URL("../../README.md", import.meta.url)), "utf8")

/** The namespaces `effect-auth/testing` publishes that the README writes through. */
const namespaces: Record<string, Readonly<Record<string, unknown>>> = {
  AuthTest: Testing.AuthTest,
  Database: Testing.Database,
  TestHttpClient: Testing.TestHttpClient,
  MockProvider: Testing.MockProvider,
  PasskeysTest: Testing.PasskeysTest,
  PhoneTest: Testing.PhoneTest,
  TwoFactorTest: Testing.TwoFactorTest,
  UsernameTest: Testing.UsernameTest,
  AnonymousTest: Testing.AnonymousTest,
  EmailOtpTest: Testing.EmailOtpTest,
  OneTapTest: Testing.OneTapTest
}

describe("README — the testing module", () => {
  it("names nothing the testing module does not export", () => {
    const text = readme()
    const missing: Array<string> = []
    let mentions = 0
    for (const [namespace, module] of Object.entries(namespaces)) {
      const pattern = new RegExp(`\\b${namespace}\\.([A-Za-z][A-Za-z0-9]*)`, "g")
      for (const match of text.matchAll(pattern)) {
        mentions += 1
        const name = match[1]!
        if (!(name in module)) missing.push(`${namespace}.${name}`)
      }
    }
    // A guard that matched nothing would pass for the wrong reason.
    assert.isAbove(mentions, 4)
    assert.deepStrictEqual([...new Set(missing)].sort(), [])
  })
})
