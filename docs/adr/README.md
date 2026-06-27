# Architecture Decision Records

Short, dated records of decisions that aren't obvious from the code. Most were
made during the Audit Round 3 security pass (2026-06-27); see `task.md`.

| ADR | Decision |
|-----|----------|
| [0001](0001-fail-closed-security-posture.md) | Security controls fail closed |
| [0002](0002-ssrf-egress-guard.md) | Egress guard against internal targets |
| [0003](0003-no-sentinel-user-id.md) | No sentinel user ids in the auth path |
| [0004](0004-typed-authz-extractors.md) | Authorization via typed extractors |
| [0005](0005-proxy-protocol-trusted-cidrs.md) | PROXY header trusted only from configured CIDRs |
| [0006](0006-bandwidth-single-source-of-truth.md) | One source of truth for bandwidth accounting |
