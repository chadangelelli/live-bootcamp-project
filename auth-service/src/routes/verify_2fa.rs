use axum::{http::StatusCode, response::IntoResponse};

pub async fn verify_2fa_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}