use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, Password, User},
};

#[axum::debug_handler]
pub async fn signup_handler(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return AuthApiError::InvalidCredentials.into_response(),
    };

    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return AuthApiError::InvalidCredentials.into_response(),
    };

    let mut user_store = state.user_store.write().await;

    if user_store.user_exists(&email).await {
        return AuthApiError::UserAlreadyExists.into_response();
    }

    let user = User::new(email, password, request.requires_2fa);

    // Return UnexpectedError if adding user fails
    if let Err(e) = user_store.add_user(user).await {
        eprintln!("Error adding user: {}", e);
        return AuthApiError::UnexpectedError.into_response();
    }

    let response = Json(SignupResponse {
        message: "User created successfully.".to_string(),
    });

    (StatusCode::CREATED, response).into_response()
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}
