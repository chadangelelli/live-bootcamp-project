use std::error::Error;

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, services::ServeDir};

mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use domain::AuthApiError;
use routes::{login, logout, signup, verify_2fa, verify_token};

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthApiError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthApiError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthApiError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthApiError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthApiError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

pub mod app_state {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::domain::{BannedTokenStore, UserStore};

    pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;
    pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;

    #[derive(Clone)]
    pub struct AppState {
        pub user_store: UserStoreType,
        pub banned_token_store: BannedTokenStoreType,
    }

    impl AppState {
        pub fn new(user_store: UserStoreType, banned_token_store: BannedTokenStoreType) -> Self {
            AppState {
                user_store,
                banned_token_store,
            }
        }
    }
}
use app_state::AppState;

pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://167.71.20.198:8000".parse()?,
            "http://167.71.20.198".parse()?,
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/signup", post(signup))
            .route("/verify_2fa", post(verify_2fa))
            .route("/verify_token", post(verify_token))
            .nest_service("/", ServeDir::new("assets"))
            .with_state(app_state)
            .layer(cors);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
