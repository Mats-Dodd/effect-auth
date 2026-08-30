# examples/basic

A complete `effect-auth` deployment in five short files.

| File | What it shows |
|---|---|
| `src/Api.ts` | Composing `AuthApi` into your own `HttpApi`, and one protected group of your own |
| `src/Todos.ts` | Reading `CurrentUser` in a handler — the whole of what an application knows about auth at request time |
| `src/Mailer.ts` | The `AuthEmails` seam (a development mailer that prints the link) |
| `src/App.ts` | `Auth.layer` wired to PGlite and the mailer, then the router — plus `Auth.layerWithOAuth` alongside it, which is the whole of what adding GitHub sign-in costs |
| `src/main.ts` | Serving it on `node:http` |

Run the server (`tsx` is not a dependency of this repo, so fetch it on the fly):

```sh
pnpm dlx tsx examples/basic/src/main.ts
```

Run the end-to-end flow instead — sign-up → verify → sign-in → protected endpoint → change password
→ sign-out, plus the reset flow, all through the generated `HttpApiClient`:

```sh
pnpm vitest run examples/basic
```

The test substitutes `AuthTest.layer` for the example's database and mailer, because reading the
token out of the verification e-mail is the only way to follow the link — the raw token exists
exactly once, in the message that carries it.
