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

// ─── #7 / #14: session-backed JWTs, logout and revocation ────────────────

async fn logout(base: &str, token: &str) -> reqwest::StatusCode {
    client()
        .post(format!("{base}/api/logout"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn login_session_logout_revokes_token() {
    let state = test_state().await;
    let uid = add_user(&state, "alice", Role::User).await;
    let base = spawn(state).await;
    let t1 = login_bearer(&base, "alice").await;
    let t2 = login_bearer(&base, "alice").await;

    let me: serde_json::Value = client()
        .get(format!("{base}/api/session"))
        .bearer_auth(&t1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user_id"], uid);
    assert_eq!(me["username"], "alice");
    assert!(me["expires_at"].as_i64().unwrap() > chrono::Utc::now().timestamp());

    let sessions_path = format!("/api/users/{uid}/sessions");
    let list: Vec<serde_json::Value> = client()
        .get(format!("{base}{sessions_path}"))
        .bearer_auth(&t1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 2, "each login is a tracked session");

    assert_eq!(logout(&base, &t1).await, 204);
    assert_eq!(get_status(&base, &t1, "/api/session").await, 401);
    assert_eq!(get_status(&base, &t2, "/api/session").await, 200);
    // Idempotent: logging out again (or with garbage) is still 204.
    assert_eq!(logout(&base, &t1).await, 204);
    assert_eq!(logout(&base, "garbage").await, 204);

    // "Sign out everywhere".
    assert_eq!(delete_status(&base, &t2, &sessions_path).await, 200);
    assert_eq!(get_status(&base, &t2, "/api/session").await, 401);
}

#[tokio::test]
async fn validly_signed_token_without_session_is_rejected() {
    let state = test_state().await;
    let uid = add_user(&state, "alice", Role::User).await;
    let secret = state.config.load().authentication.jwt_secret.clone();
    let base = spawn(state).await;
    let forged = crate::auth::jwt::create_jwt(uid, "alice", "user", &secret, 3600).unwrap();
    assert_eq!(get_status(&base, &forged, "/api/session").await, 401);
}

#[tokio::test]
async fn password_changes_revoke_sessions() {
    let state = test_state().await;
    let alice_id = add_user(&state, "alice", Role::User).await;
    add_user(&state, "root", Role::RootAdmin).await;
    let base = spawn(state).await;
    let a1 = login_bearer(&base, "alice").await;
    let a2 = login_bearer(&base, "alice").await;

    // Self-service change keeps the calling session, ends the others.
    let s = client()
        .post(format!("{base}/api/users/me/password"))
        .bearer_auth(&a1)
        .json(&serde_json::json!({
            "current_password": TEST_PASSWORD,
            "new_password": "Another-Strong-Pass-42",
        }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, 204);
    assert_eq!(get_status(&base, &a1, "/api/session").await, 200);
    assert_eq!(get_status(&base, &a2, "/api/session").await, 401);

    // Admin reset ends every session of the target.
    let root = login_bearer(&base, "root").await;
    let s = client()
        .post(format!("{base}/api/users/{alice_id}/password"))
        .bearer_auth(&root)
        .json(&serde_json::json!({"new_password": "Reset-By-Root-Pass-77"}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, 204);
    assert_eq!(get_status(&base, &a1, "/api/session").await, 401);
    assert_eq!(get_status(&base, &root, "/api/session").await, 200);
}

// ─── #64: HttpOnly cookie sessions with CSRF protection ──────────────────

#[tokio::test]
async fn cookie_login_session_csrf_and_logout() {
    let state = test_state().await;
    let uid = add_user(&state, "alice", Role::User).await;
    let base = spawn(state).await;
    let c = client();

    let res = c
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({
            "username": "alice", "password": TEST_PASSWORD, "use_cookie": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .expect("cookie mode sets a cookie")
        .to_str()
        .unwrap()
        .to_string();
    for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(set_cookie.contains(attr), "missing {attr}: {set_cookie}");
    }
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("token").is_none(),
        "no bearer token in cookie mode"
    );
    assert_eq!(body["user_id"], uid);
    let csrf = body["csrf_token"].as_str().unwrap().to_string();
    let cookie = set_cookie.split(';').next().unwrap().to_string();

    // Reads work with the cookie alone; /api/session hands back the CSRF token.
    let me: serde_json::Value = c
        .get(format!("{base}/api/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], "alice");
    assert_eq!(me["csrf_token"], csrf.as_str());

    // Unsafe requests need the CSRF header.
    let create = |csrf: Option<&str>| {
        let mut rb = c
            .post(format!("{base}/api/users/{uid}/api-keys"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"name": "k"}));
        if let Some(t) = csrf {
            rb = rb.header("x-csrf-token", t);
        }
        rb.send()
    };
    assert_eq!(create(None).await.unwrap().status(), 403);
    assert_eq!(create(Some("nope")).await.unwrap().status(), 403);
    assert_eq!(create(Some(&csrf)).await.unwrap().status(), 201);

    // Logout via cookie revokes the session and clears the cookie.
    let res = c
        .post(format!("{base}/api/logout"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert!(res
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let s = c
        .get(format!("{base}/api/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, 401);
}

#[tokio::test]
async fn bearer_clients_unaffected_by_cookie_mode() {
    let state = test_state().await;
    let uid = add_user(&state, "alice", Role::User).await;
    let base = spawn(state).await;
    let token = login_bearer(&base, "alice").await;
    // Bearer wins over any cookie, and needs no CSRF header.
    let s = client()
        .post(format!("{base}/api/users/{uid}/api-keys"))
        .bearer_auth(&token)
        .header("cookie", "cbpx_session=garbage")
        .json(&serde_json::json!({"name": "cli"}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, 201);
}

// ─── #22: /metrics scrape token ──────────────────────────────────────────

#[tokio::test]
async fn metrics_scrape_token() {
    let get = |base: String, token: Option<&'static str>| async move {
        let mut rb = client().get(format!("{base}/metrics"));
        if let Some(t) = token {
            rb = rb.bearer_auth(t);
        }
        rb.send().await.unwrap().status()
    };

    // Default: open (backwards compatible).
    let open = spawn(test_state().await).await;
    assert_eq!(get(open, None).await, 200);

    let mut config = test_config();
    config.metrics.scrape_token = Some("scrape-secret".to_string());
    let base = spawn(test_state_with(config).await).await;
    assert_eq!(get(base.clone(), None).await, 401);
    assert_eq!(get(base.clone(), Some("wrong")).await, 401);
    assert_eq!(get(base, Some("scrape-secret")).await, 200);
}

/// #22: secure by default. A non-loopback admin bind without a scrape token
/// refuses to serve /metrics unless explicitly opted out.
#[tokio::test]
async fn metrics_refused_on_exposed_bind_without_token() {
    let status = |base: String| async move {
        client()
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .status()
    };

    // The handler decides by the configured bind; the test server itself
    // still listens on loopback.
    let mut config = test_config();
    config.server.admin_bind = "0.0.0.0:8081".to_string();
    let refused = spawn(test_state_with(config.clone()).await).await;
    assert_eq!(status(refused).await, 403);

    config.metrics.allow_unauthenticated = true;
    let opted_out = spawn(test_state_with(config).await).await;
    assert_eq!(status(opted_out).await, 200);
}
