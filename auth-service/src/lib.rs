mod domain;
pub mod routes;
pub mod services;

use std::error::Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

use crate::routes::{
    login_handler, logout_handler, signup_handler, verify_2fa_handler, verify_token_handler,
};
use domain::AuthApiError;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthApiError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
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

    use crate::domain::UserStore;

    pub type UserStoreType = Arc<RwLock<dyn UserStore>>;

    #[derive(Clone)]
    pub struct AppState {
        pub user_store: UserStoreType,
    }

    impl AppState {
        pub fn new(user_store: UserStoreType) -> Self {
            AppState { user_store }
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
        let router = Router::new()
            .route("/login", post(login_handler))
            .route("/logout", post(logout_handler))
            .route("/signup", post(signup_handler))
            .route("/verify_2fa", post(verify_2fa_handler))
            .route("/verify_token", post(verify_token_handler))
            .nest_service("/", ServeDir::new("assets"))
            .with_state(app_state);

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
