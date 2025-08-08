use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState, domain::AuthApiError, services::auth::validate_token,
    utils::constants::JWT_COOKIE_NAME,
};

pub async fn verify_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    validate_token(&request.token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthApiError::MissingToken)?;
    let existing_token = cookie.value().to_owned();

    if &request.token != existing_token.as_str() {
        return Err(AuthApiError::Unauthorized);
    }

    Ok((jar, StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}
