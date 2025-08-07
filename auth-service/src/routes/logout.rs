use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    domain::AuthApiError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthApiError::MissingToken)?;
    let token = cookie.value().to_owned();

    validate_token(&token)
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    let updated_jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    Ok((updated_jar, StatusCode::OK.into_response()))
}
