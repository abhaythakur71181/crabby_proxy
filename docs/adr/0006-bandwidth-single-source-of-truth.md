# ADR-0006: One source of truth for bandwidth accounting

**Status:** Accepted (2026-06-27)

## Context
Bandwidth was tracked in three places: the in-process atomic quota tracker
(enforcement), the DB `usage` SUM (seeds the tracker), and a Redis `cache:bw`
counter written on every connection close. The Redis counter had no reader —
a pure double-write — and the overlap risked double-counting after cache
invalidation.

## Decision
The live tracker is the in-flight enforcement counter; the `usage` table is the
durable record (and the only thing re-seeded from). The dead Redis counter
(`track_bandwidth` / `incr_bandwidth` / `get_bandwidth`) is removed. The usage
writer batches inserts in one transaction and applies back-pressure before
dropping, so persistence keeps up under load.

## Consequences
No more write-only counter or per-close Redis round trip. Remaining edges
(month-rollover for long-lived tunnels, forward-path usage rows) are tracked
follow-ups.
