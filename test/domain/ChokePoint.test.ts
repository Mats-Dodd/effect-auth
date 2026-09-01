/**
 * The one rule a grep can hold and a type cannot: every session this library
 * mints goes through `SignIn.complete`.
 *
 * **Details**
 *
 * `SessionsService.createUnchecked` consults nothing — no `beforeSessionCreate`,
 * no `SignInPipeline` — so a plugin that calls it is a sign-in door with no
 * policy on it, and a person with a second factor enrolled walks straight
 * through. That is the three-path bypass this wave was written against, and it
 * is not a shape the type system can refuse: the method is on the service
 * because `SignIn` itself has to reach it.
 *
 * So it is pinned here instead. If a later plugin needs to mint a session, the
 * answer is `SignIn.complete` with the evidence it collected — not a second
 * entry in this list.
 */
// oxlint-disable-next-line effecttsgo/node-builtin-import -- a grep-level pin has to read the source text, and effect ships no FileSystem implementation for node to read it with
import { readdirSync, readFileSync } from "node:fs"
import { assert, describe, it } from "@effect/vitest"
import { fileURLToPath } from "node:url"

const srcRoot = fileURLToPath(new URL("../../src", import.meta.url))

/** Every `.ts` file under `src/`, recursively. */
const sourceFiles = (dir: string): ReadonlyArray<string> =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`
    if (entry.isDirectory()) return sourceFiles(path)
    return entry.isFile() && path.endsWith(".ts") ? [path] : []
  })

describe("domain/SignIn — the choke point", () => {
  it("`createUnchecked` is called in exactly one place, and it is SignIn.complete", () => {
    const callers = sourceFiles(srcRoot)
      .filter((path) => /\.createUnchecked\(/.test(readFileSync(path, "utf8")))
      .map((path) => path.slice(srcRoot.length + 1))
      .sort()

    assert.deepStrictEqual(callers, ["domain/SignIn.ts"])
  })
})
