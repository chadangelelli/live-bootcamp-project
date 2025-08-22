use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

use auth_service::{
    app_state::AppState,
    get_postgres_pool, get_redis_client,
    services::data_stores::{
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, postgres_user_store::PostgresUserStore,
        redis_banned_token_store::RedisBannedTokenStore,
    },
    utils::constants::{prod, DATABASE_URL, REDIS_HOSTNAME},
    Application,
};

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgres().await;
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));

    let redis_conn = Arc::new(RwLock::new(configure_redis()));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn)));

    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));

    let email_client = Arc::new(auth_service::services::mock_email_client::MockEmailClient);

    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("[auth_service::main] Failed to build app!");

    app.run()
        .await
        .expect("[auth_service::main] Failed to run app!")
}

async fn configure_postgres() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres pool");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOSTNAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
