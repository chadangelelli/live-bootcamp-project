use std::error::Error;

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use redis::{Client, RedisResult};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing;

pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use domain::AuthApiError;
use routes::{
    // login,
    // logout,
    signup,
    // verify_2fa,
    verify_token,
};

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        log_error_chain(&self);

        let (status, error_message) = match self {
            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthApiError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthApiError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthApiError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthApiError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthApiError::UnexpectedError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

fn log_error_chain(e: &(dyn Error + 'static)) {
    let separator =
        "\n-----------------------------------------------------------------------------------\n";
    let mut report = format!("{}{:?}\n", separator, e);
    let mut current = e.source();
    while let Some(cause) = current {
        let str = format!("Caused by:\n\n{:?}", cause);
        report = format!("{}\n{}", report, str);
        current = cause.source();
    }
    report = format!("{}\n{}", report, separator);
    tracing::error!("{}", report);
}

pub mod app_state {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::domain::{BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

    pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;
    pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
    pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;
    pub type EmailClientType = Arc<dyn EmailClient + Send + Sync>;

    #[derive(Clone)]
    pub struct AppState {
        pub user_store: UserStoreType,
        pub banned_token_store: BannedTokenStoreType,
        pub two_fa_code_store: TwoFACodeStoreType,
        pub email_client: EmailClientType,
    }

    impl AppState {
        pub fn new(
            user_store: UserStoreType,
            banned_token_store: BannedTokenStoreType,
            two_fa_code_store: TwoFACodeStoreType,
            email_client: EmailClientType,
        ) -> Self {
            Self {
                user_store,
                banned_token_store,
                two_fa_code_store,
                email_client,
            }
        }
    }
}
use app_state::AppState;

use crate::utils::tracing::{make_span_with_request_id, on_request, on_response};

pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://167.71.20.198:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            // .route("/login", post(login))
            // .route("/logout", post(logout))
            .route("/signup", post(signup))
            // .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .nest_service("/", ServeDir::new("assets"))
            .with_state(app_state)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        tracing::info!("listening on {}", &self.address);
        self.server.await
    }
}

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url).await
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}
