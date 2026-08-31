/**
 * Shared reading of provider-controlled JSON.
 *
 * Everything a provider sends is attacker-influenced, so nothing in this
 * package reads one of those bodies by hand any more: a `Schema` states the
 * shape that is believed, and a decoder built from it is the only way a value
 * leaves a response. `Schema.Struct` reads own properties only and ignores the
 * rest, so a body carrying `__proto__` or `constructor` cannot smuggle a value
 * in through the prototype — the guard the hand-written readers spelled out
 * with `Object.hasOwn` comes with the primitive.
 *
 * @internal
 */
import { Effect, Option, Schema, SchemaTransformation } from "effect"

/**
 * A field a provider may get wrong without it costing anybody their sign-in.
 *
 * A provider body mixes fields a decision rests on — `access_token`, `sub` —
 * with advisory ones — `expires_in`, `picture`, `scope`. A malformed advisory
 * field must read as *absent* rather than fail the whole response, which is the
 * leniency the hand-written readers had; wrapping the field's schema in this
 * keeps it.
 *
 * @internal
 */
export const lenient = <S extends Schema.Top>(
  schema: S
): Schema.middlewareDecoding<Schema.optional<S>, S["DecodingServices"]> =>
  Schema.catchDecoding<Schema.optional<S>>(() => Effect.succeed(Option.none()))(Schema.optional(schema))

/**
 * A claim believed only in the two spellings a provider states *true* with.
 *
 * Several providers encode `email_verified` as the string `"true"`. Nothing
 * else counts: a reader that treated `"false"`, `1` or `"yes"` as a claim would
 * be inventing a verified address, which is the one thing that gates linking an
 * identity onto an existing local account. Read it as
 * `field !== undefined` — absent, `false` and anything unexpected all mean no.
 *
 * @internal
 */
export const Truthy = Schema.Union([Schema.Literal(true), Schema.Literal("true")])

/**
 * A count of seconds, as a number or as the string spelling providers routinely
 * use for `expires_in`.
 *
 * A blank or non-numeric string is not a count: it reads as absent, and the
 * caller stores no expiry rather than one that already passed.
 *
 * @internal
 */
export const Seconds = Schema.Union([
  Schema.Finite,
  Schema.Trim.pipe(
    Schema.check(Schema.isMinLength(1)),
    Schema.decodeTo(Schema.Finite, SchemaTransformation.numberFromString)
  )
])

/**
 * A non-empty string, or the JSON number GitHub spells its user id with.
 *
 * @internal
 */
export const StringFromNumeric = Schema.Union([
  Schema.NonEmptyString,
  Schema.Finite.pipe(
    Schema.decodeTo(
      Schema.NonEmptyString,
      SchemaTransformation.transform({
        decode: (value: number) => `${value}`,
        encode: (value: string) => globalThis.Number(value)
      })
    )
  )
])
