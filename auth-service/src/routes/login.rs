use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, Password},
    services::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let email =
        Email::parse(request.email.clone()).map_err(|_| AuthApiError::InvalidCredentials)?;
    let password =
        Password::parse(request.password.clone()).map_err(|_| AuthApiError::InvalidCredentials)?;

    let rwlock = &state.user_store.read().await;
    let user = rwlock
        .get_user(&email)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    if password.as_ref() != user.get_password().as_ref() {
        return Err(AuthApiError::IncorrectCredentials);
    }

    let auth_cookie = generate_auth_cookie(&email).map_err(|_| AuthApiError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
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
