//! End-to-end tests for admin API authorization and sessions, driven through
//! the real router over loopback HTTP.

use super::test_support::*;
use crate::db::models::Role;

// ─── #16: API-key / session target authorization ─────────────────────────

struct Fixture {
    base: String,
    root_id: i64,
    admin_id: i64,
    admin2_id: i64,
    user_id: i64,
    user2_id: i64,
}

async fn fixture() -> Fixture {
    let state = test_state().await;
    let root_id = add_user(&state, "root", Role::RootAdmin).await;
    let admin_id = add_user(&state, "admin1", Role::Admin).await;
    let admin2_id = add_user(&state, "admin2", Role::Admin).await;
    let user_id = add_user(&state, "alice", Role::User).await;
    let user2_id = add_user(&state, "bob", Role::User).await;
    let base = spawn(state).await;
    Fixture {
        base,
        root_id,
        admin_id,
        admin2_id,
        user_id,
        user2_id,
    }
}

async fn create_key(base: &str, token: &str, target: i64) -> reqwest::StatusCode {
    client()
        .post(format!("{base}/api/users/{target}/api-keys"))
        .bearer_auth(token)
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap()
        .status()
}

async fn get_status(base: &str, token: &str, path: &str) -> reqwest::StatusCode {
    client()
        .get(format!("{base}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

async fn delete_status(base: &str, token: &str, path: &str) -> reqwest::StatusCode {
    client()
        .delete(format!("{base}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn admin_cannot_mint_api_key_for_root_or_other_admin() {
    let f = fixture().await;
    let admin = login_bearer(&f.base, "admin1").await;

    assert_eq!(create_key(&f.base, &admin, f.root_id).await, 403);
    assert_eq!(create_key(&f.base, &admin, f.admin2_id).await, 403);
    // Still allowed: own keys and regular users' keys.
    assert_eq!(create_key(&f.base, &admin, f.admin_id).await, 201);
    assert_eq!(create_key(&f.base, &admin, f.user_id).await, 201);
    // Unknown target is a 404, not a 500 from the FK.
    assert_eq!(create_key(&f.base, &admin, 99_999).await, 404);
}

#[tokio::test]
async fn admin_cannot_list_or_revoke_root_api_keys() {
    let f = fixture().await;
    let root = login_bearer(&f.base, "root").await;
    assert_eq!(create_key(&f.base, &root, f.root_id).await, 201);
    let admin = login_bearer(&f.base, "admin1").await;

    let root_keys = format!("/api/users/{}/api-keys", f.root_id);
    assert_eq!(get_status(&f.base, &admin, &root_keys).await, 403);
    assert_eq!(
        delete_status(&f.base, &admin, &format!("{root_keys}/1")).await,
        403
    );
    let admin2_keys = format!("/api/users/{}/api-keys", f.admin2_id);
    assert_eq!(get_status(&f.base, &admin, &admin2_keys).await, 403);
    // root keeps full access.
    assert_eq!(get_status(&f.base, &root, &root_keys).await, 200);
    assert_eq!(get_status(&f.base, &root, &admin2_keys).await, 200);
}

#[tokio::test]
async fn regular_user_limited_to_own_api_keys() {
    let f = fixture().await;
    let alice = login_bearer(&f.base, "alice").await;
    assert_eq!(create_key(&f.base, &alice, f.user_id).await, 201);
    assert_eq!(create_key(&f.base, &alice, f.user2_id).await, 403);
    assert_eq!(create_key(&f.base, &alice, f.root_id).await, 403);
    let bob_keys = format!("/api/users/{}/api-keys", f.user2_id);
    assert_eq!(get_status(&f.base, &alice, &bob_keys).await, 403);
}

#[tokio::test]
async fn admin_cannot_view_or_kill_root_sessions() {
    let f = fixture().await;
    let admin = login_bearer(&f.base, "admin1").await;
    let root_sessions = format!("/api/users/{}/sessions", f.root_id);
    assert_eq!(get_status(&f.base, &admin, &root_sessions).await, 403);
    assert_eq!(delete_status(&f.base, &admin, &root_sessions).await, 403);
    let user_sessions = format!("/api/users/{}/sessions", f.user_id);
    assert_eq!(get_status(&f.base, &admin, &user_sessions).await, 200);
}

// ─── #24: API key creation limits ────────────────────────────────────────

#[tokio::test]
async fn api_key_cap_and_input_validation() {
    let state = test_state().await;
    let uid = add_user(&state, "alice", Role::User).await;
    let pool = state.db_pool.clone();
    let base = spawn(state).await;
    let token = login_bearer(&base, "alice").await;
    let post = |body: serde_json::Value| {
        let (base, token) = (base.clone(), token.clone());
        async move {
            client()
                .post(format!("{base}/api/users/{uid}/api-keys"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    assert_eq!(post(serde_json::json!({"expires_in_days": -1})).await, 400);
    assert_eq!(post(serde_json::json!({"name": "x".repeat(65)})).await, 400);

    // Fill up to the cap directly (avoids hashing 25 real keys); revoked keys
    // must not count towards it.
    let now = chrono::Utc::now().timestamp();
    for i in 0..crate::admin::handlers::users::MAX_API_KEYS_PER_USER {
        sqlx::query(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name, created_at, is_active) \
             VALUES (?, ?, ?, 'n', ?, 1)",
        )
        .bind(uid)
        .bind(format!("h{i}"))
        .bind(format!("p{i}"))
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_eq!(post(serde_json::json!({"name": "one-too-many"})).await, 409);

    sqlx::query(
        "UPDATE api_keys SET is_active = 0 \
         WHERE id = (SELECT MIN(id) FROM api_keys WHERE user_id = ?)",
    )
    .bind(uid)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(post(serde_json::json!({"name": "fits-again"})).await, 201);
}

// ─── #21: typed extractor guards ─────────────────────────────────────────

#[tokio::test]
async fn extractor_guards_enforce_roles() {
    let f = fixture().await;
    let admin = login_bearer(&f.base, "admin1").await;
    let alice = login_bearer(&f.base, "alice").await;
    let c = client();

    // root_admin-only endpoints reject admins and users.
    for token in [&admin, &alice] {
        let s = c
            .put(format!("{}/api/config", f.base))
            .bearer_auth(token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(s, 403);
        assert_eq!(
            delete_status(&f.base, token, &format!("/api/users/{}", f.user2_id)).await,
            403
        );
    }
    // admin-only endpoints reject regular users.
    assert_eq!(get_status(&f.base, &alice, "/api/usage/summary").await, 403);
    assert_eq!(get_status(&f.base, &admin, "/api/usage/summary").await, 200);
    // Self-or-admin endpoints.
    let alice_quota = format!("/api/users/{}/quota", f.user_id);
    let bob_quota = format!("/api/users/{}/quota", f.user2_id);
    assert_eq!(get_status(&f.base, &alice, &alice_quota).await, 200);
    assert_eq!(get_status(&f.base, &alice, &bob_quota).await, 403);
    // No credentials at all.
    let s = c
        .get(format!("{}/api/users", f.base))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, 401);
}
