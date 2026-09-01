/**
 * The README documents sixty-odd endpoints in tables. A table is prose, and
 * prose drifts: a path renamed in `Api.ts` leaves the documented one pointing
 * at nothing, and nobody notices until somebody types it.
 *
 * So the tables are checked against the API this library actually declares —
 * every group of it, composed the way the README's own composition example
 * composes them.
 */
import { assert, describe, it } from "@effect/vitest"
// oxlint-disable-next-line effecttsgo/node-builtin-import -- a doc gate has to read the doc
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { Anonymous, EmailOtp, OneTap, Phone, TwoFactor, Username } from "../src/index.js"
import { PasskeysApiGroup } from "../src/passkeys/index.js"
import { AuthApi } from "../src/http/AuthApi.js"

const Everything = HttpApi.make("readme")
  .addHttpApi(AuthApi)
  .add(EmailOtp.EmailOtpApiGroup)
  .add(Username.UsernameApiGroup)
  .add(Anonymous.AnonymousApiGroup)
  .add(PasskeysApiGroup)
  .add(TwoFactor.TwoFactorApiGroup)
  .add(Phone.PhoneApiGroup)
  .add(OneTap.OneTapApiGroup)

describe("README", () => {
  it("every endpoint path it documents is one this library actually serves", () => {
    const document = OpenApi.fromApi(Everything)
    const served = new Set(Object.keys(document.paths))
    const readme = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8")

    const documented = [...readme.matchAll(/\|\s*`\w+`\s*\|\s*`(?:GET|POST) (\/[^`?]*)/g)].map((match) =>
      match[1]!.replace(/:(\w+)/g, "{$1}")
    )
    assert.isAbove(documented.length, 50)

    const missing = [...new Set(documented)]
      .map((path) => (path.startsWith("/auth") ? path : `/auth${path}`))
      .filter((path) => !served.has(path))
      .sort()

    assert.deepStrictEqual(missing, [])
  })

  it("every endpoint identifier it documents is one of theirs", () => {
    const readme = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8")
    const identifiers = new Set([...readme.matchAll(/\|\s*`(\w+)`\s*\|\s*`(?:GET|POST) \//g)].map((match) => match[1]!))

    const declared = new Set<string>()
    for (const group of Object.values(Everything.groups) as ReadonlyArray<{
      readonly endpoints: Readonly<Record<string, unknown>>
    }>) {
      for (const identifier of Object.keys(group.endpoints)) declared.add(identifier)
    }

    assert.deepStrictEqual([...identifiers].filter((name) => !declared.has(name)).sort(), [])
  })

  it("the ✓ column says exactly which endpoints require a session", () => {
    const document = OpenApi.fromApi(Everything)
    const readme = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8")

    // `| \`identifier\` | \`METHOD /path\` | ✓ ▲ ⧗ |` — the third cell holds the
    // marks. Keyed on the path, because an identifier is only unique within
    // its group: `verify` is email-otp's unauthenticated door *and* phone's
    // authenticated one, and they are marked differently on purpose.
    const wrong: Array<string> = []
    for (const row of readme.matchAll(/\|\s*`\w+`\s*\|\s*`(GET|POST) (\/[^`?]*)[^`]*`\s*\|([^|]*)\|/g)) {
      const path = row[2]!.replace(/:(\w+)/g, "{$1}")
      const full = path.startsWith("/auth") ? path : `/auth${path}`
      const operations = document.paths[full]
      const operation = operations === undefined ? undefined : operations[row[1] === "GET" ? "get" : "post"]
      if (operation === undefined) continue

      // A session-bound endpoint is the one the middleware put a security
      // scheme on; `401` in its responses is the same statement read twice.
      const authenticated = operation.security !== undefined && operation.security.length > 0
      const documented = row[3]!.includes("✓")
      if (documented !== authenticated) {
        wrong.push(`${full}: documented ${documented}, declares ${authenticated}`)
      }
    }

    assert.isAbove(readme.split("✓").length - 1, 20)
    assert.deepStrictEqual(wrong.sort(), [])
  })
})
