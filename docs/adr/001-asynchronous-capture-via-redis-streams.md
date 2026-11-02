# ADR-001: Asynchronous capture via Redis Streams

- Status: Accepted
- Date: 2026-11-02

## The problem

Recording what attackers do is the whole point of Mirage, so every request has to be
captured. But the code that answers a request can't afford to wait on the recording.
We want tier 0 responses in under 50 ms at around 500 requests per second on a single
VPS, and we don't want someone running a scanner against us to be able to slow the
honeypot down just by making the database busy.

The obvious approach is to insert a row into PostgreSQL from the request handler.
That ties our latency and uptime to the database, and it turns every burst of scanner
traffic into a burst of single-row inserts. We'd rather not.

## What we decided

The request path only drops an event onto a Redis Stream and moves on. Separate worker
processes read from that stream and write to PostgreSQL.

On the publishing side, `CaptureMiddleware` builds a `CapturedRequest` and the
`StreamPublisher` appends it with `XADD ... MAXLEN ~ N`, giving Redis one second to
answer. Publishing never raises. If it fails, we log the event id (never the
attacker's payload), drop the event, and answer the request as usual. A broken Redis
should not take the honeypot down with it.

On the consuming side, workers join a consumer group and acknowledge a batch only
after they have handled it. That gives us at-least-once delivery: if a worker dies
halfway through, its unacknowledged entries are picked up again by another worker
after a short idle period, and that idle period doubles as the retry delay. Because a
retry can mean seeing an event twice, every event carries a unique `event_id` and the
persister inserts with `ON CONFLICT (event_id, ts) DO NOTHING`. Seeing an event twice
is therefore harmless.

Events that keep failing get special treatment. Retried entries are processed one at a
time, so a single malformed event can't drag its healthy neighbours down with it, and
after `max_deliveries` attempts the entry is moved to a dead-letter stream
(`<stream>:dead`) and acknowledged. It stops blocking the group, but we still have it
to look at.

Redis itself runs with AOF persistence (`everysec`). The stream is capped with
`MAXLEN ~`, and Redis has a `maxmemory` limit with `noeviction`, so if the stream ever
outgrows memory, `XADD` starts failing instead of the kernel killing Redis outright.

A nice side effect: the later pipeline stages (enrichment, detection, classification
and so on) are just more consumer groups reading the same stream at their own pace.
The request path doesn't need to know they exist.

## What this gets us

Response latency and availability no longer depend on PostgreSQL. If the database goes
away, the stream grows and the workers catch up when it comes back. Writes are batched
into one multi-row insert instead of one per request. And adding an analysis stage
means adding a consumer, not touching the request path.

## What it costs, and where it falls short

The honest headline: **we do not fully meet the "zero event loss" goal.** Once an event
is in the stream, it's safe: delivery is at-least-once, failures end up in the
dead-letter stream, and AOF protects against a restart. Before that point it's best
effort. If Redis can't be reached at the moment of `XADD`, the event is gone.

We've already seen this happen in practice: after a Redis restart, the first event can
hit a stale connection in the pool and get dropped. The planned fixes are one
immediate retry on connection errors, and later a small local spool for events that
couldn't be published (there's a `TODO` for it in `StreamPublisher`).

There are two smaller gaps. With AOF at `everysec`, a Redis crash can lose roughly the
last second of events. And if the workers fall so far behind that the stream holds
more than `MAXLEN` unread entries, the oldest ones get trimmed before anyone reads
them. That's why stream lag needs an alert, which we'll add with the metrics in
stage 2.

A few other things to keep in mind. A request shows up in PostgreSQL only after the
consumer's next batch, usually within a few seconds, so anything that has to react
inside a live session (tier routing, world state) must read Redis, not the database.
The dead-letter stream can contain duplicates if a worker crashes between writing to it
and acknowledging, though `requests` never will. And Redis is now a critical piece of
the system, which is why it stays off the public network.

## What we looked at instead

- **Insert directly in the handler.** The simplest option, and nothing is lost once a
  request has been answered. But it couples latency and uptime to PostgreSQL and can't
  absorb bursts. We ruled it out.
- **Kafka or RabbitMQ.** Better delivery guarantees, but a lot more to run on one VPS
  for a few hundred events a second. We need Redis anyway for budgets, world state and
  caches, so we'd rather use what's already there.
- **PostgreSQL as the queue** (an outbox table or `LISTEN/NOTIFY`). One datastore
  instead of two, but it puts the database straight back on the request path.
- **A local append-only file as the main buffer.** No network dependency, but it needs
  its own reader, rotation and handling for several processes. It makes more sense as
  a fallback for failed publishes than as the primary path.
