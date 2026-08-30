/**
 * Serves {@link AppLive} on `node:http`.
 *
 * `HttpRouter.toWebHandler` turns the application layer into a plain
 * `(Request) => Promise<Response>`; everything below is the twenty lines of
 * glue between that and `node:http`, which a real deployment gets from its
 * platform package instead.
 *
 * Run it with `pnpm --filter effect-auth exec tsx examples/basic/src/main.ts`,
 * or any TypeScript runner.
 */
import { createServer } from "node:http"
import { HttpRouter } from "effect/unstable/http"
import { AppLive, baseUrl } from "./App.js"

const { dispose, handler } = HttpRouter.toWebHandler(AppLive)

const port = Number(new URL(baseUrl).port || "3000")

const server = createServer((incoming, outgoing) => {
  const chunks: Array<Buffer> = []
  incoming.on("data", (chunk: Buffer) => chunks.push(chunk))
  incoming.on("end", () => {
    const method = incoming.method ?? "GET"
    const hasBody = method !== "GET" && method !== "HEAD"
    const request = new Request(new URL(incoming.url ?? "/", baseUrl), {
      method,
      headers: incoming.headers as Record<string, string>,
      ...(hasBody ? { body: Buffer.concat(chunks) } : {})
    })

    handler(request).then(
      async (response) => {
        // `getSetCookie` keeps several `Set-Cookie` headers separate, which a
        // plain iteration over the headers would fold into one and break.
        const headers: Record<string, string | Array<string>> = {}
        response.headers.forEach((value, key) => {
          if (key.toLowerCase() !== "set-cookie") headers[key] = value
        })
        const setCookie = response.headers.getSetCookie()
        if (setCookie.length > 0) headers["set-cookie"] = setCookie

        outgoing.writeHead(response.status, headers)
        outgoing.end(response.body === null ? undefined : Buffer.from(await response.arrayBuffer()))
      },
      (error: unknown) => {
        console.error(error)
        outgoing.writeHead(500)
        outgoing.end()
      }
    )
  })
})

server.listen(port, () => console.log(`effect-auth example listening on ${baseUrl}`))

const shutdown = () => {
  server.close()
  void dispose()
}
process.once("SIGINT", shutdown)
process.once("SIGTERM", shutdown)
