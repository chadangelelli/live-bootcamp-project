use axum::{http::StatusCode, response::IntoResponse};

pub async fn login_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}