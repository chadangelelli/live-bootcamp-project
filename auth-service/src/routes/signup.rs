use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, Password, User, UserStoreError},
};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let password =
        Password::parse(request.password, false).map_err(|_| AuthApiError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);
    let result = state.user_store.write().await.add_user(user).await;
    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(SignupResponse {
                message: "User created successfully.".to_string(),
            }),
        )),
        Err(UserStoreError::UserAlreadyExists) => Err(AuthApiError::UserAlreadyExists),
        Err(e) => {
            eprintln!("Error adding user: {}", e);
            Err(AuthApiError::UnexpectedError(e.into()))
        }
    }
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
