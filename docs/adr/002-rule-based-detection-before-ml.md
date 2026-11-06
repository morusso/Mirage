# ADR-002: Rule-based detection before ML

- Status: Accepted
- Date: 2026-11-06

## The problem

For every request I want to know what it is trying to do: SQL injection, XSS, template
injection, path traversal, command injection, Log4Shell, or just a known scanner
announcing itself. That feeds the dashboards now and the router and the analyst later.

The fashionable answer is a classifier. I'm not going to start there, because at this
point I have almost no traffic and no labelled data. Whatever model I trained today
would learn my guesses, and I'd have no honest way to tell whether it works.

## What I decided

Detection is a set of explicit rules that run in the detector worker, off the request
path, as another consumer of the capture stream (see ADR-001).

A rule is a small class with a unique name (`sqli.union_select`), a coarse category
(`sqli`) and a severity, and a `match` method that returns the offending text or
nothing. Most rules are just regular expressions over chosen parts of the request.
There are around thirty payload rules in six families, plus one rule per scanner tool
(sqlmap, nuclei, ffuf, gobuster, masscan, zgrab), which only look at the `User-Agent`.

Everything a rule sees is attacker-controlled, so the framework is defensive:

- **Normalization before matching.** Path, query, body and header values are URL-decoded
  repeatedly (up to three rounds, since attackers double-encode to slip past filters),
  stripped of NUL bytes and capped at 8 KiB per part. Rules match against that, so
  they don't each have to know about `%2527`.
- **Linear-time regexes only.** No nested quantifiers. A crafted payload must not be
  able to make the worker spin, because the worker is exactly what I'm asking it to
  inspect.
- **Isolation.** The registry catches an exception from a rule, logs the rule name
  (never the payload) and carries on with the rest. One buggy rule can't stop
  detection or crash the worker.
- **One match per rule per request**, excerpt truncated to 200 characters. The unique
  index on `detections (request_id, request_ts, rule)` plus `ON CONFLICT DO NOTHING`
  makes redelivered events harmless, same idea as the persister.

A labelled corpus (`tests/data/detector_corpus.json`, 64 requests, 17 of them ordinary
traffic that must fire nothing) is run against all families registered together. It
checks the exact set of categories, so it catches both misses and families firing on
each other's traffic. Whenever real data shows a missed attack or a false alarm, the
fix starts with a new corpus entry.

## Why rules first

They're explainable. When a detection fires, I can say which rule and which text. When
it's wrong, I can fix that rule and prove the fix with a test.

They need no training data, which I don't have yet. They are also cheap and predictable:
a regex pass per request fits inside a single worker at a few hundred requests per
second, with no GPU and no model latency.

And the detections will become the labels. Once sessions have run for a while, the
stored detections, with the analyst's reports, are the first real dataset I could
train or evaluate something against.

## What it costs, and where it falls short

Rules only find what someone thought to write down. A novel payload, or a known one
that's obfuscated beyond three decode rounds or split across parameters, will pass. A
missed detection is silent. I only learn about it if I notice it in the raw requests.

Some rules will also fire on innocent text (a blog post that mentions `UNION SELECT`).
For a honeypot that's tolerable, since nothing is blocked on the basis of a detection,
but it does skew the numbers in the dashboards.

Scanner signatures trust the default `User-Agent`. A tool run with a changed one isn't
recognised here. Catching that is the job of behaviour-based session classification in
stage 4, which uses timing and path patterns instead.

Rules are per request, with no memory. A multi-step attack that looks harmless one
request at a time is invisible at this layer.

Finally, the rule set is something I have to keep maintaining.

## What I looked at instead

- **An ML classifier from the start.** The right long-term direction for fuzzy cases,
  but with no labelled traffic it would be a black box I can't evaluate. I'd rather
  collect labels from rules first and revisit.
- **An LLM per request.** Flexible and good at unusual payloads, but it adds latency,
  cost and exposure to prompt injection on exactly the text I distrust most. The
  model is reserved for classifying and analysing whole sessions, where it's worth it.
- **Off-the-shelf WAF rule sets (such as OWASP CRS).** Mature and broad, but built to
  block with a low false-positive rate, not to label and categorise. Their engine
  also doesn't fit a Python worker, and I couldn't unit-test individual rules the
  same way. Their patterns are still a good source of ideas for new rules.
