/**
 * Serves {@link AppLive} on `node:http`.
 *
 * `HttpRouter.toWebHandler` turns the application layer into a plain
 * `(Request) => Promise<Response>`; everything below is the glue between that
 * and `node:http`, which a real deployment gets from its platform package
 * instead.
 *
 * **Details**
 *
 * The glue is one Effect rather than a chain of callbacks: the body is read, the
 * handler is called and the response is written inside `Effect.gen`, so a
 * failure anywhere along it is a `Cause` that gets logged and answered `500`
 * instead of an unhandled rejection. The server and the handler are both
 * acquired with `Effect.acquireRelease`, so `SIGINT` closes the listener and
 * disposes the layer — the database included — by interrupting one fiber.
 *
 * Run it with `pnpm dlx tsx examples/basic/src/main.ts`, or any TypeScript
 * runner.
 */
// `node:http` is the one import this file exists to make: it is a *server*, and
// the API the rule points at — `HttpClient` from `effect/unstable/http` — is an
// HTTP client. Core ships no Node server adapter either (`HttpServer.make` asks
// its caller for precisely the `serve` glue written below), so a deployment
// deletes this file in favour of its platform's `HttpServer` layer rather than
// rewriting it against a different Effect API.
// oxlint-disable-next-line effecttsgo/node-builtin-import
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http"
import { Effect, Fiber } from "effect"
import { HttpRouter } from "effect/unstable/http"
import { AppLive, baseUrl } from "./App.js"

/**
 * Node's request headers as a `Request`'s.
 *
 * A header sent twice arrives from Node as an `Array<string>`, so this is an
 * `append` per value rather than the cast to `Record<string, string>` that would
 * quietly drop the second one.
 */
const toRequestHeaders = (incoming: IncomingHttpHeaders): Headers => {
  const headers = new Headers()
  for (const [name, value] of Object.entries(incoming)) {
    if (typeof value === "string") headers.append(name, value)
    else if (Array.isArray(value)) {
      for (const one of value) headers.append(name, one)
    }
  }
  return headers
}

/** The request body, as the `Uint8Array` a `Request` is willing to take. */
const readBody = (incoming: IncomingMessage): Effect.Effect<Uint8Array<ArrayBuffer>> =>
  Effect.callback<Uint8Array<ArrayBuffer>>((resume) => {
    const chunks: Array<Buffer> = []
    incoming.on("data", (chunk: Buffer) => chunks.push(chunk))
    incoming.on("end", () => resume(Effect.succeed(new Uint8Array(Buffer.concat(chunks)))))
    incoming.on("error", (error) => resume(Effect.die(error)))
  })

/** Writes a `Response` back out over Node's `ServerResponse`. */
const writeResponse = (outgoing: ServerResponse, response: Response) =>
  Effect.gen(function* () {
    // `getSetCookie` keeps several `Set-Cookie` headers separate, which a plain
    // iteration over the headers would fold into one and break.
    const headers: Record<string, string | Array<string>> = {}
    response.headers.forEach((value, key) => {
      if (key.toLowerCase() !== "set-cookie") headers[key] = value
    })
    const setCookie = response.headers.getSetCookie()
    if (setCookie.length > 0) headers["set-cookie"] = setCookie

    const body = response.body === null ? undefined : Buffer.from(yield* Effect.promise(() => response.arrayBuffer()))
    outgoing.writeHead(response.status, headers)
    outgoing.end(body)
  })

/**
 * One request, end to end.
 *
 * Nothing below the `catchCause` can escape: a defect in the handler, a socket
 * that dies mid-body, a response that cannot be encoded — all of them are logged
 * and answered `500`, which is the whole of what the two `console` calls this
 * replaced were doing.
 */
const respond = (
  origin: string,
  handler: (request: Request) => Promise<Response>,
  incoming: IncomingMessage,
  outgoing: ServerResponse
) =>
  Effect.gen(function* () {
    const method = incoming.method ?? "GET"
    const hasBody = method !== "GET" && method !== "HEAD"
    const body = hasBody ? yield* readBody(incoming) : undefined
    const request = new Request(new URL(incoming.url ?? "/", origin), {
      method,
      headers: toRequestHeaders(incoming.headers),
      ...(body === undefined ? {} : { body })
    })

    const response = yield* Effect.promise(() => handler(request))
    yield* writeResponse(outgoing, response)
  }).pipe(
    Effect.catchCause((cause) =>
      Effect.gen(function* () {
        yield* Effect.logError("effect-auth example: request failed", cause)
        outgoing.writeHead(500)
        outgoing.end()
      })
    )
  )

/**
 * The server, for as long as the fiber running it is not interrupted.
 *
 * `Effect.never` is what keeps it up: the two `acquireRelease` finalizers above
 * it run in reverse on interruption, so the listener stops accepting before the
 * application layer is disposed.
 */
const main = Effect.gen(function* () {
  const origin = yield* baseUrl
  const port = Number(new URL(origin).port || "3000")

  const { handler } = yield* Effect.acquireRelease(
    Effect.sync(() => HttpRouter.toWebHandler(AppLive)),
    ({ dispose }) => Effect.promise(dispose)
  )

  // Node hands each request back through a callback, so the per-request Effect
  // is forked with the services this fiber is running under — its logger
  // included — rather than with a fresh default runtime.
  const runFork = Effect.runForkWith(yield* Effect.context())

  const server = yield* Effect.acquireRelease(
    Effect.sync(() =>
      createServer((incoming, outgoing) => {
        runFork(respond(origin, handler, incoming, outgoing))
      })
    ),
    (server) =>
      Effect.callback<void>((resume) => {
        server.close(() => resume(Effect.void))
      })
  )

  yield* Effect.callback<void>((resume) => {
    server.listen(port, () => resume(Effect.void))
  })
  yield* Effect.log(`effect-auth example listening on ${origin}`)
  return yield* Effect.never
})

const fiber = Effect.runFork(Effect.scoped(main))

const shutdown = () => {
  Effect.runFork(Fiber.interrupt(fiber))
}
process.once("SIGINT", shutdown)
process.once("SIGTERM", shutdown)
