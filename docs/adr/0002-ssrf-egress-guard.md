# ADR-0002: Egress guard against internal targets

**Status:** Accepted (2026-06-27)

## Context
Target filtering was name-based and applied before DNS resolution; nothing
checked the *resolved* IP. An authenticated client could reach RFC1918 hosts,
loopback services, or the cloud metadata endpoint (169.254.169.254) — classic
proxy SSRF — and DNS rebinding bypassed the name filter.

## Decision
After resolution, `self_loop::is_blocked_egress` rejects private / loopback /
link-local / ULA / CGNAT / unspecified / multicast / v4-mapped addresses,
gated by `filtering.block_private_targets`. Checking the connected IP also
defends against rebinding.

## Consequences
Default is `false` to preserve same-machine / internal proxying (the product's
original use case); deployments that only proxy to the public internet set it
`true`. A future refinement is an explicit per-target CIDR allowlist instead of
a global toggle.
