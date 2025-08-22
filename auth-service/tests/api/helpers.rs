use std::{str::FromStr, sync::Arc};

use reqwest::{cookie::Jar, Client};
use serde_json::json;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Connection, Executor, PgConnection, PgPool,
};
use tokio::sync::RwLock;

use auth_service::{
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
    domain::{LoginAttemptId, TwoFACode},
    get_postgres_pool, get_redis_client,
    services::{
        data_stores::{
            postgres_user_store::PostgresUserStore,
            redis_banned_token_store::RedisBannedTokenStore, HashmapTwoFACodeStore,
        },
        mock_email_client::MockEmailClient,
    },
    utils::{
        constants::{test, DATABASE_URL},
        REDIS_HOSTNAME,
    },
    Application,
};
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub db_name: String,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));

        let redis_conn = Arc::new(RwLock::new(
            get_redis_client(REDIS_HOSTNAME.to_owned())
                .expect("Failed to create Redis client")
                .get_connection()
                .expect("Failed to get Redis connection"),
        ));
        let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn)));

        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));

        let email_client = Arc::new(MockEmailClient);

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client,
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("[auth_service::helpers] Failed to build app!");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());

        let http_client = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        TestApp {
            address,
            cookie_jar,
            db_name,
            http_client,
            banned_token_store,
            two_fa_code_store,
        }
    }

    pub async fn get_path(&self, path: &str) -> reqwest::Response {
        self.http_client
            .get(&format!("{}", &self.address))
            .send()
            .await
            .expect(&format!(
                "[auth_service::TestApp] Failed to get '{}' path.",
                path
            ))
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("[auth_service::TestApp] Failed to post signup request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute login request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute logout request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn clean_up(db_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        Ok(delete_database(db_name).await)
    }
}

// TODO: discuss this with Bogdan and/or Arnaud
impl Drop for TestApp {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        tokio::spawn(async move {
            match TestApp::clean_up(&db_name).await {
                Ok(_) => println!("Successfully cleaned up database: {}", db_name),
                Err(err) => {
                    panic!("Failed to clean up database: {}. Error: {}", db_name, err);
                }
            };
        });
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", uuid::Uuid::new_v4())
}

pub async fn signup(
    app: &TestApp,
    email: &str,
    password: &str,
    require_2fa: bool,
) -> reqwest::Response {
    let signup_body = json!({
        "email": &email,
        "password": &password,
        "requires2FA": require_2fa,
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);
    signup_response
}

pub async fn login(
    app: &TestApp,
    email: &str,
    password: &str,
    require_2fa: bool,
) -> reqwest::Response {
    let login_body = json!({
        "email": &email,
        "password": &password,
    });
    let success_status_code = if require_2fa { 206 } else { 200 };
    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), success_status_code);
    login_response
}

pub async fn signup_and_login(app: &TestApp, email: &str, password: &str) -> reqwest::Response {
    signup(app, email, password, false).await;
    login(app, email, password, false).await
}

pub fn get_random_login_attempt_id() -> String {
    format!("{}", LoginAttemptId::generate_random().as_ref())
}

pub fn get_random_two_fa_code() -> String {
    format!("{}", TwoFACode::generate_random().as_ref())
}

async fn configure_postgresql() -> (PgPool, String) {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!
    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);

    // Create a new connection pool and return it
    let pool = get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!");

    (pool, db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
                "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}
