import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts", "examples/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    passWithNoTests: true,
    // Every database-backed test boots its own PGlite instance and runs the
    // migrations, and `sequence.concurrent` starts a file's worth of them at
    // once. The five-second default is not enough for the first of them on a
    // cold machine.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fakeTimers: {
      toFake: undefined
    },
    sequence: {
      concurrent: true
    }
  }
})
