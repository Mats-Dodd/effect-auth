import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts", "examples/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    passWithNoTests: true,
    // Tests share one database per file via @effect/vitest layer() blocks. The
    // lower timeouts are deliberate tripwires against per-test database boots
    // creeping back in. hookTimeout stays higher to cover layer() beforeAll.
    testTimeout: 10_000,
    hookTimeout: 15_000,
    fakeTimers: {
      toFake: undefined
    },
    sequence: {
      concurrent: true
    }
  }
})
