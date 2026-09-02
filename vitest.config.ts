import { defineConfig } from "vitest/config"

/** Which backend the suite is about to run against. See `src/testing/Database.ts`. */
// oxlint-disable-next-line effecttsgo/process-env -- vitest reads this file as plain Node before any Effect runtime exists; `Config` needs one
const dialect = process.env["EFFECT_AUTH_TEST_DATABASE"] ?? "pglite"

/**
 * A container-backed run pays for a server start inside the first `layer()`
 * block's `beforeAll`. Everything else keeps the 15 s tripwire.
 */
const containerBacked = dialect === "pg" || dialect === "mysql"

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts", "examples/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    passWithNoTests: true,
    // Module isolation off: every test file in a worker shares one module
    // registry, which is what makes `src/testing`'s module-level memos per
    // worker rather than per file, and what stops every file re-importing the
    // whole tree. Measured on this tree, 2026-09-02, 1482 tests on PGlite:
    // 32.3 s isolated at four workers, 20.2 s here, 35.6 s at two. (The plan's
    // own numbers, taken before the wave, were 143 s / 61 s / 41 s.) All
    // passing, no timeout tripped. A change that needs isolation back has to
    // say what state it leaks.
    isolate: false,
    // Tests share one database per `layer()` block. The lower timeouts are
    // deliberate tripwires against per-test database boots creeping back in;
    // testTimeout is one and stays one.
    testTimeout: 10_000,
    hookTimeout: containerBacked ? 120_000 : 15_000,
    fakeTimers: {
      toFake: undefined
    },
    sequence: {
      concurrent: true
    }
  }
})
