use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// User group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub max_connections: Option<i32>,
    pub bandwidth_limit_mb: Option<i64>,
    pub rate_limit_rps: Option<i32>,
    pub rate_limit_burst: Option<i32>,
    pub allowed_protocols: Option<String>,
    pub allowed_targets: Option<String>,
    pub blocked_targets: Option<String>,
    pub access_schedule: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// User group with member count (for list endpoint)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroupWithCount {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub max_connections: Option<i32>,
    pub bandwidth_limit_mb: Option<i64>,
    pub rate_limit_rps: Option<i32>,
    pub rate_limit_burst: Option<i32>,
    pub allowed_protocols: Option<String>,
    pub allowed_targets: Option<String>,
    pub blocked_targets: Option<String>,
    pub access_schedule: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub member_count: i64,
}

/// Group member with user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberDetail {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub joined_at: i64,
}

/// Create a new user group
pub async fn create_group(
    pool: &SqlitePool,
    name: &str,
    description: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO user_groups (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
    )
    .bind(name)
    .bind(description)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get group by ID
pub async fn get_group(pool: &SqlitePool, id: i64) -> Result<Option<UserGroup>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, description, max_connections, bandwidth_limit_mb, rate_limit_rps, rate_limit_burst, allowed_protocols, allowed_targets, blocked_targets, access_schedule, created_at, updated_at FROM user_groups WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| UserGroup {
        id: r.get(0),
        name: r.get(1),
        description: r.get(2),
        max_connections: r.get(3),
        bandwidth_limit_mb: r.get(4),
        rate_limit_rps: r.get(5),
        rate_limit_burst: r.get(6),
        allowed_protocols: r.get(7),
        allowed_targets: r.get(8),
        blocked_targets: r.get(9),
        access_schedule: r.get(10),
        created_at: r.get(11),
        updated_at: r.get(12),
    }))
}

/// List all groups with member counts
pub async fn list_groups(pool: &SqlitePool) -> Result<Vec<UserGroupWithCount>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT g.id, g.name, g.description, g.max_connections, g.bandwidth_limit_mb, g.rate_limit_rps, g.rate_limit_burst, g.allowed_protocols, g.allowed_targets, g.blocked_targets, g.access_schedule, g.created_at, g.updated_at, COUNT(m.user_id) as member_count FROM user_groups g LEFT JOIN user_group_members m ON g.id = m.group_id GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| UserGroupWithCount {
            id: r.get(0),
            name: r.get(1),
            description: r.get(2),
            max_connections: r.get(3),
            bandwidth_limit_mb: r.get(4),
            rate_limit_rps: r.get(5),
            rate_limit_burst: r.get(6),
            allowed_protocols: r.get(7),
            allowed_targets: r.get(8),
            blocked_targets: r.get(9),
            access_schedule: r.get(10),
            created_at: r.get(11),
            updated_at: r.get(12),
            member_count: r.get(13),
        })
        .collect())
}

/// Delete a group
pub async fn delete_group(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM user_groups WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Add user to group
pub async fn add_user_to_group(
    pool: &SqlitePool,
    user_id: i64,
    group_id: i64,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT OR IGNORE INTO user_group_members (user_id, group_id, added_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(group_id)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remove user from group
pub async fn remove_user_from_group(
    pool: &SqlitePool,
    user_id: i64,
    group_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM user_group_members WHERE user_id = ? AND group_id = ?")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get groups for a user
pub async fn get_user_groups(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<UserGroup>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT g.id, g.name, g.description, g.max_connections, g.bandwidth_limit_mb, g.rate_limit_rps, g.rate_limit_burst, g.allowed_protocols, g.allowed_targets, g.blocked_targets, g.access_schedule, g.created_at, g.updated_at FROM user_groups g INNER JOIN user_group_members m ON g.id = m.group_id WHERE m.user_id = ? ORDER BY g.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| UserGroup {
            id: r.get(0),
            name: r.get(1),
            description: r.get(2),
            max_connections: r.get(3),
            bandwidth_limit_mb: r.get(4),
            rate_limit_rps: r.get(5),
            rate_limit_burst: r.get(6),
            allowed_protocols: r.get(7),
            allowed_targets: r.get(8),
            blocked_targets: r.get(9),
            access_schedule: r.get(10),
            created_at: r.get(11),
            updated_at: r.get(12),
        })
        .collect())
}

/// Get members of a group with user details
pub async fn get_group_members(
    pool: &SqlitePool,
    group_id: i64,
) -> Result<Vec<GroupMemberDetail>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT u.id, u.username, u.role, m.added_at FROM user_group_members m INNER JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY m.added_at",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| GroupMemberDetail {
            user_id: r.get(0),
            username: r.get(1),
            role: r.get(2),
            joined_at: r.get(3),
        })
        .collect())
}
