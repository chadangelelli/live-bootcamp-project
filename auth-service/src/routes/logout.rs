use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::utils::auth::validate_token;
use crate::utils::constants::JWT_COOKIE_NAME;
use crate::{app_state::AppState, domain::AuthApiError};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthApiError::MissingToken)?;
    let token = cookie.value().to_owned();

    validate_token(&token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    {
        let mut banned_token_store = state.banned_token_store.write().await;
        banned_token_store
            .add_token(token)
            .await
            .map_err(|_| AuthApiError::UnexpectedError)?;
    }

    let updated_jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    Ok((updated_jar, StatusCode::OK.into_response()))
}
