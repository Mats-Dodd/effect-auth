/**
 * Refuses a publish driven by npm.
 *
 * The package's top-level `exports` map points at `./src/*.ts` so that the repo
 * itself, the tests and `examples/` resolve the sources; `publishConfig.exports`
 * is what rewrites those entry points onto `./dist` in the published tarball.
 * That rewrite is applied by pnpm and yarn — *not* by `npm publish`, which would
 * happily ship a package whose entry points are TypeScript sources Node cannot
 * load. The failure is silent at publish time and total at install time, so it
 * is worth one guard.
 *
 * Publish with `pnpm publish`.
 */
const execPath = process.env.npm_execpath ?? ""
const userAgent = process.env.npm_config_user_agent ?? ""

const isNpm = /npm-cli\.js$|[\\/]npm$/.test(execPath) || userAgent.startsWith("npm/")

if (isNpm) {
  console.error(
    [
      "effect-auth: refusing to publish with npm.",
      "",
      "The published entry points come from `publishConfig.exports`, which npm does not apply;",
      "an npm-published tarball would expose ./src/*.ts entry points that Node cannot load.",
      "",
      "Use `pnpm publish` instead."
    ].join("\n")
  )
  process.exit(1)
}
