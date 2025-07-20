use axum::{http::StatusCode, response::IntoResponse};

pub async fn signup_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}