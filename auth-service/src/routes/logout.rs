use axum::{http::StatusCode, response::IntoResponse};

pub async fn logout_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}