/**
 * `effect-auth/testing` — a complete deployment for a test suite.
 *
 * **Gotchas**
 *
 * This entry point imports `@effect/sql-pglite`. Install it as a dev
 * dependency; nothing under `effect-auth` or `effect-auth/client` depends on
 * it, so a production bundle never sees it.
 *
 * @since 1.0.0
 */
export * as AuthTest from "./TestLayer.js"
