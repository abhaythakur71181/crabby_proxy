# ADR-0005: PROXY header trusted only from configured CIDRs

**Status:** Accepted (2026-06-27)

## Context
With `proxy_protocol_enabled`, the parsed source IP drove IP/geo/rate filtering,
but the header was trusted from any peer — so a direct client could forge it and
spoof its source IP.

## Decision
The PROXY v1 header is parsed only when the immediate socket peer is in
`server.proxy_protocol_trusted_cidrs`; otherwise it is left unparsed and the
real socket address is used. An empty list (with the feature enabled) trusts
nobody — operators must list their load balancers.

## Consequences
Enabling PROXY protocol now requires configuring the upstream CIDRs (fail
closed). Untrusted peers that send a header simply fail protocol detection.
