use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, Password},
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let password =
        Password::parse(request.password).map_err(|_| AuthApiError::InvalidCredentials)?;

    let rwlock = &state.user_store.read().await;
    let user = rwlock.get_user(&email).await;

    if let Ok(user) = user {
        let correct_password = user.get_password();

        if password.as_ref() == correct_password.as_ref() {
            return Ok(StatusCode::OK.into_response());
        }
    }

    Err(AuthApiError::IncorrectCredentials)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct LoginResponse {
    pub message: String,
}
