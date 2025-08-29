use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let email =
        Email::parse(Secret::new(request.email)).map_err(|_| AuthApiError::InvalidCredentials)?;

    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    let code = TwoFACode::parse(request.code).map_err(|_| AuthApiError::InvalidCredentials)?;

    let (correct_login_attempt_id, correct_code) = {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;

        let correct_values = two_fa_code_store
            .get_code(&email)
            .await
            .map_err(|_| AuthApiError::IncorrectCredentials)?;

        let _: () = two_fa_code_store
            .remove_code(&email)
            .await
            .map_err(|e| AuthApiError::UnexpectedError(e.into()))?;

        correct_values
    };

    if login_attempt_id != correct_login_attempt_id || code != correct_code {
        return Err(AuthApiError::IncorrectCredentials);
    }

    let auth_cookie = generate_auth_cookie(&email).map_err(|e| AuthApiError::UnexpectedError(e))?;
    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, (StatusCode::OK.into_response())))
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub code: String,
}
