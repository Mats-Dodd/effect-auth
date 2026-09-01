/**
 * `pnpm install` in *this* repo has to do two things beyond fetching packages:
 * patch the TypeScript and oxlint binaries so the Effect rules exist at all
 * (`effect-tsgo patch --oxlint`), and install the git hooks (`lefthook install`).
 *
 * Neither of those may happen in a *consumer's* install. `prepare` runs for a
 * dependency installed from a git URL, and there it would patch the consumer's
 * toolchain — a package has no business rewriting the binaries of the project
 * that depends on it, and there is no repo to hang git hooks on either.
 *
 * The discriminator is INIT_CWD: npm/pnpm set it to the directory the install
 * was *invoked* from. For a developer running `pnpm install` here that is this
 * repo root; for a consumer it is the consumer's root while cwd is our checkout
 * deep inside their store. Same directory means "we are the project", anything
 * else (including INIT_CWD being unset) means "we are a dependency" and we exit 0.
 *
 * Plain Node ESM on purpose: this runs before anything is built, and `effect`
 * itself may not be resolvable yet. The scripts/** override in .oxlintrc.json is
 * what allows console and loose boolean checks here.
 */
import { spawnSync } from "node:child_process"
import { realpathSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

// Resolved against this repo's own node_modules/.bin so the script works when
// run directly (`node scripts/prepare.mjs`), not only under a package-manager
// lifecycle where .bin is already on PATH.
const bin = (name) => resolve(dirname(fileURLToPath(import.meta.url)), "..", "node_modules", ".bin", name)

const sameDir = (a, b) => {
  try {
    return realpathSync(a) === realpathSync(b)
  } catch {
    return false
  }
}

const initCwd = process.env.INIT_CWD
if (!initCwd || !sameDir(resolve(initCwd), process.cwd())) {
  process.exit(0)
}

for (const [command, ...args] of [
  ["effect-tsgo", "patch", "--oxlint"],
  ["lefthook", "install"]
]) {
  const result = spawnSync(bin(command), args, { stdio: "inherit", shell: process.platform === "win32" })
  if (result.error) {
    console.error(`prepare: failed to run \`${command} ${args.join(" ")}\`: ${result.error.message}`)
    process.exit(1)
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1)
  }
}
