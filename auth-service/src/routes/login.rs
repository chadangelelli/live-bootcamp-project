use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, LoginAttemptId, Password, TwoFACode},
    utils::auth::generate_auth_cookie,
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

    let user_store_guard = state.user_store.read().await;
    let user = match user_store_guard.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return Err(AuthApiError::IncorrectCredentials),
    };

    if password.as_ref() != user.get_password().as_ref() {
        return Err(AuthApiError::IncorrectCredentials);
    }

    match user.requires_2fa() {
        true => handle_2fa(&email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    let login_attempt_id = LoginAttemptId::generate_random();
    let two_fa_code = TwoFACode::generate_random();

    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;
        two_fa_code_store
            .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
            .await
            .map_err(|_| AuthApiError::UnexpectedError)?;
    }

    // TODO: send 2FA code via the email client. Return `AuthAPIError::UnexpectedError` if the operation fails.
    let subject = "Your Let's Get Rusty 2FA Code";
    let content = format!("Your 2FA code is: {}", &two_fa_code.as_ref());

    state
        .email_client
        .send_email(email, subject, &content)
        .await
        .map_err(|_| AuthApiError::UnexpectedError)?;

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
    }));

    Ok((jar, (StatusCode::PARTIAL_CONTENT, response)))
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    let auth_cookie = generate_auth_cookie(email).map_err(|_| AuthApiError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((
        updated_jar,
        (StatusCode::OK, Json(LoginResponse::RegularAuth)),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
