# ADR-003: Hybrid LLM architecture

- Status: Accepted (tier 0 and tier 1 are built; tier 2 and the router are not yet)
- Date: 2026-11-13

## The problem

Static templates make a poor honeypot for anyone who looks twice: the same canned
answer for every unknown path, no memory of what the attacker just did. A language
model can answer anything and sound like the service, which is what keeps a human
talking. But a model is slow, costs compute or money, and is the one component an
attacker controls the input of, on purpose.

I want the model's reach without three things: a flaky model turning into an error page
that gives the honeypot away, an attacker using my model as a free GPU, and a prompt
injection turning the fake service into something that tells them what it is.

## What I decided

Answers come from tiers, cheapest first, and the model is never on the only path.

- **Tier 0: cache and templates.** Jinja2 templates for known bait (WordPress,
  phpMyAdmin, `.git`, Actuator) and a Redis cache of earlier model answers. Instant.
  It is also the fallback for everything below it.
- **Tier 1: a small local model** (Ollama, 7B class, quantized) behind an
  OpenAI-compatible client with a hard timeout. It answers requests tier 0 does not
  know. One client with per-tier configuration serves Ollama, vLLM and hosted APIs, so
  changing the model is a settings change, not code.
- **Tier 2: a stronger model**, for sessions that look like a person. Not built yet.
  It will use the same client with a second `TierConfig`, and it is the reason the
  router in the design (`ModelRouter`) exists: the choice of tier lives in one place.

The model is treated as an untrusted, unreliable component:

- **Output is validated, input is data.** The model must return one JSON object that
  parses into `GeneratedResponse` (status 200-599, sanitized headers, bounded body).
  Anything else is a failure. The request goes into the prompt as escaped JSON between
  markers that carry a random per-call nonce, and the system message names those
  markers and says everything inside is data. The model has no tools, and nothing it
  writes is executed.
- **A leak guard on the way out.** A valid answer that repeats the system prompt or its
  nonce is refused too, because an injection that works would otherwise be served to
  the attacker verbatim.
- **Every failure degrades to tier 0.** A timeout, an unreachable endpoint, bad output,
  a leak, or an unavailable world all end in the static answer the endpoint had before
  it had a model. Failed attempts are not cached, so the next request tries again.
- **Budgets degrade, they do not refuse.** Tokens (estimated up front, corrected after
  the call, refunded if the model was never reached) are charged atomically across IP,
  subnet and a global dimension in one Redis Lua script. Over budget means tier 0, never
  a 429: a scanner that gets a normal answer does not learn that it hit a limit. If
  Redis cannot answer, the budget fails closed, which also means tier 0.
- **The model does not own the world.** What the attacker created must stay true: a
  POST that makes user 1042 and a later GET must agree. Base data comes from a per-world
  seed, the attacker's changes live in a Redis delta, and the model is shown only the
  slice of the world the request is about. It may propose `state_updates`, but they are
  validated and applied by `WorldState`; the model never writes to Redis.
- **Answers are cached per world.** The cache key holds the world id and a world version
  that increases on every applied update. The same request gets the same answer inside
  one world (a changing answer is a fingerprinting tell), worlds never share entries,
  and a cached answer cannot outlive the object it described. An answer that itself
  changed the world is not cached.
- **A flag guards it.** `MIRAGE_TIER1_ENABLED` is off by default, so `main` stays
  deployable with tier 0 only.

## Why this shape

A local model first because the payloads are personal data and often hostile; they stay
on the machine, there is no per-token bill, and an attacker flooding it costs me
latency, not money. The strong model is reserved for the few sessions worth it, which is
also where an external API, if I use one, is easiest to justify under GDPR.

One OpenAI-compatible client because the interface is the stable part and the model is
the part I expect to change.

Failing to tier 0 instead of erroring because the honeypot's job is to look like a
working service. An outage or an exhausted budget must be invisible from outside, and a
static answer is almost always acceptable.

Validation and a leak guard instead of trusting the prompt, because no prompt is
injection-proof. The prompt makes an attack unlikely and the validation bounds what a
successful one can do: it can change what the fake service says, not what the honeypot
does.

## What it costs

- **Latency.** A tier 1 answer is up to the timeout (3 s target) against milliseconds
  for tier 0, and a fast static answer next to a slow generated one is itself a tell.
  Equalizing latency across tiers is planned work, not done.
- **Cache misses on world changes.** Any applied update invalidates that world's cached
  answers, including unrelated ones. That is simple and safe; if tier 1 load shows it
  hurts, the version can be split per kind.
- **A world that needs Redis.** Reading the world version needs Redis, so while Redis is
  down tier 1 is skipped entirely and every request gets the static answer.
- **The leak guard is narrow.** It catches the system prompt coming back. It does not
  catch the model claiming to be an AI or dropping its persona in its own words; that is
  left to the prompt, and to the injection suite (`tests/security`), which gets a new
  case whenever one is found.
- **Quality is limited by a 7B model.** Hallucinations that contradict the world are
  reduced by showing it only the facts that matter and by seeded data, not removed.

## What I'm not deciding yet

How tier 2 is chosen (interest score, ASN budget, dynamic multipliers) and whether it
runs locally or through an API. Both depend on session data I don't have yet, and are
left for the router work.
