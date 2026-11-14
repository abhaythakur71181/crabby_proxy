pub mod api_keys;
pub mod api_keys_crud;
#[allow(dead_code)]
pub mod approval_requests;
#[allow(dead_code)]
pub mod approvals;
#[allow(dead_code)]
pub mod audit_log;
pub mod connection;
pub mod groups;
#[allow(dead_code)]
pub mod models;
pub mod quota;
#[allow(dead_code)]
pub mod sessions;
pub mod usage;
pub mod users;

#[cfg_attr(not(test), allow(unused_imports))]
pub use connection::create_pool;
pub use connection::run_migrations;

/// Default page size for list queries when the caller does not ask for one.
pub const DEFAULT_LIST_LIMIT: i64 = 500;
/// Hard upper bound on a single list page, whatever the caller asks for.
pub const MAX_LIST_LIMIT: i64 = 1000;

/// LIMIT/OFFSET window applied to every list query so no endpoint returns an
/// unbounded, ever-growing result set (#32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub limit: i64,
    pub offset: i64,
}

impl Page {
    /// Build a page from optional caller input: missing limit falls back to
    /// [`DEFAULT_LIST_LIMIT`], limit is clamped to `1..=MAX_LIST_LIMIT`, and a
    /// negative offset is treated as 0.
    pub fn new(limit: Option<i64>, offset: Option<i64>) -> Self {
        Self {
            limit: limit.unwrap_or(DEFAULT_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT),
            offset: offset.unwrap_or(0).max(0),
        }
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new(None, None)
    }
}

#[cfg(test)]
mod page_tests {
    use super::*;

    #[test]
    fn page_defaults_and_clamps() {
        assert_eq!(
            Page::default(),
            Page {
                limit: DEFAULT_LIST_LIMIT,
                offset: 0
            }
        );
        assert_eq!(
            Page::new(Some(0), Some(-5)),
            Page {
                limit: 1,
                offset: 0
            }
        );
        assert_eq!(Page::new(Some(1_000_000), Some(10)).limit, MAX_LIST_LIMIT);
        assert_eq!(
            Page::new(Some(20), Some(40)),
            Page {
                limit: 20,
                offset: 40
            }
        );
    }
}
