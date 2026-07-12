# Wildcard IP Approvals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let approval `client_ip` be a pattern (octet wildcard, CIDR, IPv6) so a rotating-IP client is approved for a range once, not per-IP.

**Architecture:** New `ip_pattern` module parses and matches patterns. `db::approvals::is_ip_approved` fetches a user's active patterns and matches the concrete connecting IP in Rust (the per-IP boolean cache in `AppState` is unchanged, so the hot path stays O(1)). Both approval entry-point handlers validate the pattern and surface a warning for broad patterns.

**Tech Stack:** Rust, axum, sqlx (sqlite), `ipnet` (already a dependency), tokio test.

## Global Constraints

- Binary crate — modules are registered in `src/main.rs` with `mod <name>;`.
- Tests live in-file under `#[cfg(test)] mod tests` and run via `cargo test --bin crabby_proxy <filter>`.
- DB tests build an in-memory pool with `SqlitePool::connect(":memory:")` and create needed tables inline (see `src/db/users.rs::setup_test_db`).
- No database schema change: `approvals.client_ip` / `approval_requests.client_ip` stay `TEXT`.
- `ApiError::bad_request(msg)` produces `400`.
- End every commit message with the repo trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `ip_pattern` module — model, parse, match, broad-detection

**Files:**
- Create: `src/ip_pattern.rs`
- Modify: `src/main.rs` (add `mod ip_pattern;` in the module list, alphabetical — between `mod ip_filter;` and `mod metrics;`)
- Test: in-file `#[cfg(test)] mod tests` in `src/ip_pattern.rs`

**Interfaces:**
- Produces:
  - `pub enum IpPattern { Any, V4Octets([Option<u8>;4]), Cidr(ipnet::IpNet), Exact(std::net::IpAddr) }`
  - `pub struct IpPatternError(pub String)` implementing `std::fmt::Display`
  - `IpPattern::parse(s: &str) -> Result<IpPattern, IpPatternError>`
  - `IpPattern::matches(&self, ip: std::net::IpAddr) -> bool`
  - `IpPattern::is_broad(&self) -> bool`

- [ ] **Step 1: Create the module file with the implementation**

Create `src/ip_pattern.rs`:

```rust
//! Client-IP approval patterns: exact IP, octet-wildcard IPv4, CIDR, or "any".
//!
//! Approvals are keyed on the connecting client IP. Mobile clients rotate IPs
//! constantly, so an approval may be stored as a pattern (`140.11.11.*`,
//! `140.11.0.0/16`, `*`) and matched against the concrete connecting IP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed client-IP approval pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPattern {
    /// `*` (or `*.*.*.*`) — matches every IP, v4 and v6.
    Any,
    /// IPv4 octet wildcard: `Some(v)` is a fixed octet, `None` a wildcard.
    /// Only produced with 1..=3 fixed octets (0 → `Any`, 4 → `Exact`).
    V4Octets([Option<u8>; 4]),
    /// CIDR range, v4 or v6.
    Cidr(ipnet::IpNet),
    /// A single fully-specified IP address.
    Exact(IpAddr),
}

/// Invalid-pattern error carrying a human-readable reason.
#[derive(Debug, PartialEq, Eq)]
pub struct IpPatternError(pub String);

impl std::fmt::Display for IpPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid IP pattern: {}", self.0)
    }
}

impl IpPattern {
    /// Parse a pattern string. Precedence: `*` → Any; contains `/` → CIDR;
    /// contains `:` → IPv6 exact; 4 dotted octets (each `*` or 0..=255) →
    /// octet form (collapsing to Any/Exact at the extremes); else error.
    pub fn parse(s: &str) -> Result<IpPattern, IpPatternError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(IpPatternError("empty pattern".into()));
        }
        if s == "*" {
            return Ok(IpPattern::Any);
        }
        if s.contains('/') {
            return s
                .parse::<ipnet::IpNet>()
                .map(IpPattern::Cidr)
                .map_err(|e| IpPatternError(format!("bad CIDR '{s}': {e}")));
        }
        if s.contains(':') {
            return s
                .parse::<Ipv6Addr>()
                .map(|a| IpPattern::Exact(IpAddr::V6(a)))
                .map_err(|e| IpPatternError(format!("bad IPv6 address '{s}': {e}")));
        }
        // IPv4: exactly 4 dotted parts, each "*" or 0..=255.
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(IpPatternError(format!(
                "expected 4 octets or '*' in '{s}'"
            )));
        }
        let mut octets: [Option<u8>; 4] = [None; 4];
        let mut fixed = 0;
        for (i, p) in parts.iter().enumerate() {
            if *p == "*" {
                octets[i] = None;
            } else {
                let v: u8 = p
                    .parse()
                    .map_err(|_| IpPatternError(format!("bad octet '{p}' in '{s}'")))?;
                octets[i] = Some(v);
                fixed += 1;
            }
        }
        match fixed {
            0 => Ok(IpPattern::Any),
            4 => Ok(IpPattern::Exact(IpAddr::V4(Ipv4Addr::new(
                octets[0].unwrap(),
                octets[1].unwrap(),
                octets[2].unwrap(),
                octets[3].unwrap(),
            )))),
            _ => Ok(IpPattern::V4Octets(octets)),
        }
    }

    /// True if `ip` falls in this pattern. An IPv4 pattern never matches an
    /// IPv6 address and vice versa.
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            IpPattern::Any => true,
            IpPattern::Exact(a) => *a == ip,
            IpPattern::Cidr(net) => net.contains(&ip),
            IpPattern::V4Octets(pat) => match ip {
                IpAddr::V4(v4) => {
                    let actual = v4.octets();
                    pat.iter()
                        .zip(actual.iter())
                        .all(|(p, a)| match p {
                            Some(v) => v == a,
                            None => true,
                        })
                }
                IpAddr::V6(_) => false,
            },
        }
    }

    /// True when the pattern approves a very large address space (advisory —
    /// used to warn an operator, not to reject).
    pub fn is_broad(&self) -> bool {
        match self {
            IpPattern::Any => true,
            IpPattern::Exact(_) => false,
            // 1 fixed octet ⇒ ~/8; 0 would have been Any.
            IpPattern::V4Octets(pat) => pat.iter().filter(|o| o.is_some()).count() <= 1,
            IpPattern::Cidr(net) => match net {
                ipnet::IpNet::V4(n) => n.prefix_len() <= 8,
                ipnet::IpNet::V6(n) => n.prefix_len() <= 32,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_star_as_any() {
        assert_eq!(IpPattern::parse("*").unwrap(), IpPattern::Any);
        assert_eq!(IpPattern::parse("*.*.*.*").unwrap(), IpPattern::Any);
    }

    #[test]
    fn parses_octet_wildcard() {
        assert_eq!(
            IpPattern::parse("140.11.11.*").unwrap(),
            IpPattern::V4Octets([Some(140), Some(11), Some(11), None])
        );
        assert_eq!(
            IpPattern::parse("140.*.*.*").unwrap(),
            IpPattern::V4Octets([Some(140), None, None, None])
        );
    }

    #[test]
    fn full_ipv4_is_exact() {
        assert_eq!(
            IpPattern::parse("140.11.11.5").unwrap(),
            IpPattern::Exact(ip("140.11.11.5"))
        );
    }

    #[test]
    fn parses_cidr_v4_and_v6() {
        assert!(matches!(
            IpPattern::parse("140.11.0.0/16").unwrap(),
            IpPattern::Cidr(_)
        ));
        assert!(matches!(
            IpPattern::parse("2401:4900::/32").unwrap(),
            IpPattern::Cidr(_)
        ));
    }

    #[test]
    fn parses_ipv6_exact() {
        assert_eq!(
            IpPattern::parse("2401:4900::1234").unwrap(),
            IpPattern::Exact(ip("2401:4900::1234"))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(IpPattern::parse("").is_err());
        assert!(IpPattern::parse("not-an-ip").is_err());
        assert!(IpPattern::parse("140.11.*").is_err()); // only 3 parts
        assert!(IpPattern::parse("999.1.1.1").is_err()); // octet out of range
        assert!(IpPattern::parse("140.11.0.0/99").is_err()); // bad prefix
    }

    #[test]
    fn octet_wildcard_matching() {
        let p = IpPattern::parse("140.11.11.*").unwrap();
        assert!(p.matches(ip("140.11.11.5")));
        assert!(p.matches(ip("140.11.11.255")));
        assert!(!p.matches(ip("140.11.12.5")));
        // never matches v6
        assert!(!p.matches(ip("2401:4900::1")));
    }

    #[test]
    fn cidr_matching_is_family_sensitive() {
        let p = IpPattern::parse("140.11.0.0/16").unwrap();
        assert!(p.matches(ip("140.11.99.99")));
        assert!(!p.matches(ip("140.12.0.1")));
        assert!(!p.matches(ip("2401:4900::1"))); // v4 net, v6 ip
    }

    #[test]
    fn any_matches_both_families() {
        let p = IpPattern::Any;
        assert!(p.matches(ip("8.8.8.8")));
        assert!(p.matches(ip("2401:4900::1")));
    }

    #[test]
    fn broad_detection_boundaries() {
        assert!(IpPattern::parse("*").unwrap().is_broad());
        assert!(IpPattern::parse("140.*.*.*").unwrap().is_broad()); // 1 fixed octet
        assert!(!IpPattern::parse("140.11.*.*").unwrap().is_broad()); // 2 fixed
        assert!(!IpPattern::parse("140.11.11.5").unwrap().is_broad());
        assert!(IpPattern::parse("10.0.0.0/8").unwrap().is_broad());
        assert!(!IpPattern::parse("10.0.0.0/9").unwrap().is_broad());
        assert!(IpPattern::parse("2401::/32").unwrap().is_broad());
        assert!(!IpPattern::parse("2401::/33").unwrap().is_broad());
    }
}
```

- [ ] **Step 2: Register the module**

In `src/main.rs`, add the line `mod ip_pattern;` immediately after `mod ip_filter;`.

- [ ] **Step 3: Run the tests — expect PASS**

Run: `cargo test --bin crabby_proxy ip_pattern::`
Expected: all `ip_pattern::tests::*` pass (11 tests).

- [ ] **Step 4: Commit**

```bash
git add src/ip_pattern.rs src/main.rs
git commit -m "feat(approvals): IP pattern parser (octet wildcard, CIDR, IPv6)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Match wildcard patterns in `is_ip_approved`

**Files:**
- Modify: `src/db/approvals.rs` (replace the body of `is_ip_approved`, lines ~33-51)
- Test: in-file `#[cfg(test)] mod tests` in `src/db/approvals.rs` (new)

**Interfaces:**
- Consumes: `crate::ip_pattern::IpPattern::parse` / `matches` (Task 1); existing `create_approval(pool, user_id, client_ip, approved_by, duration_hours, reason)`.
- Produces: `is_ip_approved(pool, user_id, client_ip) -> Result<bool, sqlx::Error>` — unchanged signature, now pattern-aware.

- [ ] **Step 1: Write the failing tests**

Append to the end of `src/db/approvals.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                approved_by INTEGER NOT NULL,
                approved_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                is_expired BOOLEAN DEFAULT 0,
                is_terminated BOOLEAN DEFAULT 0,
                terminated_by INTEGER,
                terminated_at INTEGER,
                termination_reason TEXT,
                reason TEXT,
                approval_duration_hours INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn wildcard_pattern_matches_concrete_ip() {
        let pool = setup().await;
        create_approval(&pool, 1, "140.11.11.*", 99, 24, None)
            .await
            .unwrap();
        assert!(is_ip_approved(&pool, 1, "140.11.11.5").await.unwrap());
        assert!(!is_ip_approved(&pool, 1, "140.11.12.5").await.unwrap());
    }

    #[tokio::test]
    async fn exact_pattern_still_matches() {
        let pool = setup().await;
        create_approval(&pool, 1, "8.8.8.8", 99, 24, None)
            .await
            .unwrap();
        assert!(is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
        assert!(!is_ip_approved(&pool, 1, "8.8.4.4").await.unwrap());
    }

    #[tokio::test]
    async fn expired_and_terminated_never_match() {
        let pool = setup().await;
        let past = chrono::Utc::now().timestamp() - 10;
        // expired '*' grant
        sqlx::query(
            "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, approval_duration_hours) VALUES (1,'*',9,0,?,1)",
        )
        .bind(past)
        .execute(&pool)
        .await
        .unwrap();
        // active-but-terminated '*' grant
        let fut = chrono::Utc::now().timestamp() + 3600;
        sqlx::query(
            "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, is_terminated, approval_duration_hours) VALUES (1,'*',9,0,?,1,1)",
        )
        .bind(fut)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
    }

    #[tokio::test]
    async fn corrupt_pattern_is_skipped_not_fatal() {
        let pool = setup().await;
        create_approval(&pool, 1, "not-an-ip", 9, 24, None)
            .await
            .unwrap();
        // Skipped without error; no match.
        assert!(!is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --bin crabby_proxy approvals::tests::`
Expected: `wildcard_pattern_matches_concrete_ip` FAILS (old exact SQL match can't match `140.11.11.*`). (`exact_pattern_still_matches` may already pass.)

- [ ] **Step 3: Replace the `is_ip_approved` implementation**

In `src/db/approvals.rs`, replace the whole `is_ip_approved` function (currently the exact-match `COUNT(*)` query) with:

```rust
/// Check if an IP is approved for a user (active, non-expired, non-terminated).
///
/// Fetches the user's active approval patterns and matches the concrete IP in
/// Rust, so wildcard / CIDR / IPv6 patterns are honored — not just exact IPs.
/// A stored pattern that fails to parse (corrupt row) is skipped and logged,
/// so one bad row cannot fail-closed the whole check.
pub async fn is_ip_approved(
    pool: &SqlitePool,
    user_id: i64,
    client_ip: &str,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let patterns = sqlx::query_scalar::<_, String>(
        "SELECT client_ip FROM approvals WHERE user_id = ? AND expires_at > ? AND is_expired = 0 AND is_terminated = 0",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await?;

    let ip: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        // Not a concrete IP (shouldn't happen from the proxy path) — nothing to match.
        Err(_) => return Ok(false),
    };

    for pat_str in patterns {
        match crate::ip_pattern::IpPattern::parse(&pat_str) {
            Ok(pat) if pat.matches(ip) => return Ok(true),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                "skipping unparseable approval pattern '{}' for user {}: {}",
                pat_str,
                user_id,
                e
            ),
        }
    }
    Ok(false)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --bin crabby_proxy approvals::tests::`
Expected: all 4 pass.

- [ ] **Step 5: Commit**

```bash
git add src/db/approvals.rs
git commit -m "feat(approvals): match wildcard/CIDR patterns in is_ip_approved

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Validate pattern + warn on broad, in both approval handlers

**Files:**
- Modify: `src/ip_pattern.rs` (add `validate_approval_pattern` helper + test)
- Modify: `src/admin/handlers/approval_requests.rs` (`create_request`, ~line 80)
- Modify: `src/admin/handlers/approvals.rs` (`create_approval`, ~line 39)

**Interfaces:**
- Consumes: `IpPattern::parse` / `is_broad` (Task 1); `ApiError::bad_request` (`src/admin/handlers/models.rs`).
- Produces: `crate::ip_pattern::validate_approval_pattern(client_ip: &str) -> Result<Option<String>, IpPatternError>` — `Ok(Some(warning))` when broad, `Ok(None)` when fine, `Err` when invalid.

- [ ] **Step 1: Write the failing test for the helper**

Add these tests inside the existing `#[cfg(test)] mod tests` in `src/ip_pattern.rs`:

```rust
    #[test]
    fn validate_returns_warning_for_broad() {
        let w = validate_approval_pattern("*").unwrap();
        assert!(w.is_some());
        let w = validate_approval_pattern("140.*.*.*").unwrap();
        assert!(w.is_some());
    }

    #[test]
    fn validate_no_warning_for_narrow() {
        assert_eq!(validate_approval_pattern("140.11.11.5").unwrap(), None);
        assert_eq!(validate_approval_pattern("140.11.11.*").unwrap(), None);
    }

    #[test]
    fn validate_errors_on_invalid() {
        assert!(validate_approval_pattern("not-an-ip").is_err());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bin crabby_proxy ip_pattern::tests::validate`
Expected: FAIL — `validate_approval_pattern` not found.

- [ ] **Step 3: Add the helper**

In `src/ip_pattern.rs`, after the `impl IpPattern` block (before `#[cfg(test)]`), add:

```rust
/// Validate a client-IP pattern submitted for an approval request or grant.
/// Returns `Ok(Some(warning))` when the pattern is broad (approves a very large
/// address space — surfaced to the operator but still allowed), `Ok(None)` when
/// the pattern is fine, and `Err` when the pattern is syntactically invalid.
pub fn validate_approval_pattern(client_ip: &str) -> Result<Option<String>, IpPatternError> {
    let pat = IpPattern::parse(client_ip)?;
    Ok(pat.is_broad().then(|| {
        format!(
            "pattern '{}' approves this user from a very large IP range",
            client_ip.trim()
        )
    }))
}
```

- [ ] **Step 4: Run to verify the helper tests pass**

Run: `cargo test --bin crabby_proxy ip_pattern::`
Expected: all pass (14 tests).

- [ ] **Step 5: Wire `create_request`**

In `src/admin/handlers/approval_requests.rs`, in `create_request`, replace the block from the `// User always requests for themselves` comment down through the audit-log call and the final `Ok((...))` with:

```rust
    // Validate the client-IP pattern; reject invalid, warn (but allow) broad.
    let warning = crate::ip_pattern::validate_approval_pattern(&payload.client_ip)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // User always requests for themselves
    let id = approval_requests::create_request(
        &state.db_pool,
        current_user_id,
        &payload.client_ip,
        payload.duration_hours,
        payload.reason.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create approval request: {}", e);
        ApiError::internal("Failed to create approval request")
    })?;

    // Audit log
    let detail = format!(
        "duration: {}h{}",
        payload.duration_hours,
        if warning.is_some() { ", broad_pattern=true" } else { "" }
    );
    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "approval_request_created",
        Some("approval_request"),
        Some(&id.to_string()),
        Some(&detail),
        Some(&payload.client_ip),
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "user_id": current_user_id,
            "status": "pending",
            "requested_at": now,
            "warning": warning,
        })),
    ))
```

- [ ] **Step 6: Wire `create_approval`**

In `src/admin/handlers/approvals.rs`, in `create_approval`, immediately after the `current_user.require_admin()?;` line, insert:

```rust
    // Validate the client-IP pattern; reject invalid, warn (but allow) broad.
    let warning = crate::ip_pattern::validate_approval_pattern(&payload.client_ip)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
```

Then change the audit-log `detail` argument. Replace:

```rust
        Some(&format!(
            "User {}, duration: {}h",
            payload.user_id, payload.duration_hours
        )),
```

with:

```rust
        Some(&format!(
            "User {}, duration: {}h{}",
            payload.user_id,
            payload.duration_hours,
            if warning.is_some() { ", broad_pattern=true" } else { "" }
        )),
```

Then surface the warning in the response. Change the `ApprovalResponse` struct (top of file) to add a warning field — replace:

```rust
#[derive(Debug, Serialize)]
pub struct ApprovalResponse {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub approved_by: i64,
    pub approved_at: i64,
    pub expires_at: i64,
    pub reason: Option<String>,
    pub duration_hours: i32,
}
```

with:

```rust
#[derive(Debug, Serialize)]
pub struct ApprovalResponse {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub approved_by: i64,
    pub approved_at: i64,
    pub expires_at: i64,
    pub reason: Option<String>,
    pub duration_hours: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}
```

And in the `Ok((StatusCode::CREATED, Json(ApprovalResponse { ... })))` construction at the end of `create_approval`, add `warning,` as the last field (after `duration_hours: payload.duration_hours,`).

- [ ] **Step 7: Build, clippy, run the full suite**

Run: `cargo build --bin crabby_proxy && cargo clippy --bin crabby_proxy --all-targets && cargo test --bin crabby_proxy`
Expected: builds, clippy clean, all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/ip_pattern.rs src/admin/handlers/approval_requests.rs src/admin/handlers/approvals.rs
git commit -m "feat(approvals): validate IP pattern + warn on broad grants

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §1 pattern model + parse precedence → Task 1 ✓
- §1 matches (family-sensitive) → Task 1 (`octet_wildcard_matching`, `cidr_matching_is_family_sensitive`, `any_matches_both_families`) ✓
- §1 is_broad thresholds → Task 1 (`broad_detection_boundaries`) ✓
- §2 fetch-and-match in `is_ip_approved`, cache unchanged (signature preserved) → Task 2 ✓
- §2 corrupt row skipped/logged → Task 2 (`corrupt_pattern_is_skipped_not_fatal`) ✓
- §3 validate → 400 → Task 3 (`validate_errors_on_invalid` + handler `map_err(bad_request)`) ✓
- §3 broad warning (audit tag + response field), warn-but-allow → Task 3 Steps 5-6 ✓
- §4 no schema change → confirmed; tables/columns untouched ✓
- §5 tests → Tasks 1-3 all TDD ✓

**Placeholder scan:** none — every step has concrete code/commands.

**Type consistency:** `IpPattern`, `IpPatternError`, `parse`/`matches`/`is_broad`, `validate_approval_pattern(&str) -> Result<Option<String>, IpPatternError>` used identically across tasks. `is_ip_approved` signature unchanged. `ApprovalResponse.warning` added with `skip_serializing_if`.
