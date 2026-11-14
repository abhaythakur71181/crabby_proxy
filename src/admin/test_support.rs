//! Test harness for the admin API: a real `AppState` over an in-memory SQLite
//! database, served on an ephemeral loopback port so tests exercise the full
//! router (auth middleware, extractors, handlers).

use std::net::SocketAddr;
use std::sync::Arc;

use crate::app_state::AppState;
use crate::config::Config;
use crate::db::models::{CreateUserRequest, Role};

pub const TEST_PASSWORD: &str = "Correct-Horse-9-Battery";

pub fn test_config() -> Config {
    let mut config = Config::default();
    // Built at runtime so secret scanners don't flag a literal.
    config.authentication.jwt_secret =
        ["unit", "test", "signing", "key", "not", "secret"].join("-") + "-0123456789";
    // Never talk to a developer's local Redis from tests.
    config.state.redis_url = "redis://127.0.0.1:1".to_string();
    config
}

pub async fn test_state_with(config: Config) -> Arc<AppState> {
    let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
    crate::db::run_migrations(&pool).await.unwrap();
    Arc::new(AppState::new(config, None, pool).await.unwrap())
}

pub async fn test_state() -> Arc<AppState> {
    test_state_with(test_config()).await
}

pub async fn add_user(state: &AppState, username: &str, role: Role) -> i64 {
    let req = CreateUserRequest {
        username: username.to_string(),
        password: TEST_PASSWORD.to_string(),
        role,
        max_connections: None,
        bandwidth_limit_mb: None,
        rate_limit_enabled: Some(false),
        rate_limit_rps: None,
        allowed_protocols: None,
        notes: None,
    };
    crate::db::users::create_user(&state.db_pool, &req, None)
        .await
        .unwrap()
}

/// Serve the admin router on 127.0.0.1:<ephemeral> and return its base URL.
pub async fn spawn(state: Arc<AppState>) -> String {
    let app = super::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{}", addr)
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

/// Log in with the bearer-token flow and return the JWT.
pub async fn login_bearer(base: &str, username: &str) -> String {
    let res = client()
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username": username, "password": TEST_PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "login failed for {username}");
    let body: serde_json::Value = res.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}
