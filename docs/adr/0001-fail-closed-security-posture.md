# ADR-0001: Security controls fail closed

**Status:** Accepted (2026-06-27)

## Context
Several controls previously allowed traffic on error or missing data: the geo
filter allowed unknown countries even in allowlist mode, the Redis rate limiter
allowed on Redis error, and the connection-limit validator allowed on a
state-backend error. An attacker who can induce a backend fault could thereby
disable the control.

## Decision
On the security path, ambiguity denies. Geo allowlist mode denies unknown
countries; the distributed rate limiter denies on Redis error; the
connection-limit validator denies on count error (consistent with the quota
validator, which already failed closed).

## Consequences
A backend outage can deny legitimate traffic — acceptable for a security proxy,
and preferable to silently lifting a control. Availability-sensitive operators
can fall back to the in-process limiter rather than the distributed one.
