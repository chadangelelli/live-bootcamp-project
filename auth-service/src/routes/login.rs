use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthApiError, Email, LoginAttemptId, Password, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    println!("---------------> [login] 1. ");
    let email = Email::parse(Secret::new(request.email.clone()))
        .map_err(|_| AuthApiError::InvalidCredentials)?;
    println!("---------------> [login] 2. email: {email:?}");

    let password = Password::parse(request.password.clone(), false)
        .map_err(|_| AuthApiError::InvalidCredentials)?;
    println!("---------------> [login] 3. password: {password:?}");

    let user = {
        let user_store = state.user_store.read().await;
        match user_store.validate_user(&email, &password).await {
            Ok(user) => user,
            Err(_) => {
                return Err(AuthApiError::IncorrectCredentials);
            }
        }
    };
    println!("---------------> [login] 4. user: {user:?}");

    match user.requires_2fa {
        true => handle_2fa(&email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

#[tracing::instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    println!("\t---------------> [handle_2fa] 1.");
    let login_attempt_id = LoginAttemptId::generate_random();
    println!("\t---------------> [handle_2fa] 2.");
    let two_fa_code = TwoFACode::generate_random();
    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;
        let _ = two_fa_code_store
            .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
            .await
            .map_err(|e| AuthApiError::UnexpectedError(e.into()));
    }
    println!("\t---------------> [handle_2fa] 3.");

    let subject = "Your Let's Get Rusty 2FA Code";
    println!("\t---------------> [handle_2fa] 4.");
    let content = format!(
        "Your 2FA code is: {}",
        &two_fa_code.as_ref().expose_secret()
    );
    println!("\t---------------> [handle_2fa] 5.");

    if let Err(e) = state
        .email_client
        .send_email(&email, subject, &content)
        .await
    {
        println!("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
        println!("%%%%%%%%%%%%%%% Err: {e:?}");
        println!("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
        return Err(AuthApiError::UnexpectedError(e.into()));
    }
    println!("\t---------------> [handle_2fa] 6.");

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().expose_secret().to_string(),
    }));
    println!("\t---------------> [handle_2fa] 7.");

    let auth_cookie = generate_auth_cookie(email).map_err(|e| AuthApiError::UnexpectedError(e))?;
    println!("\t---------------> [handle_2fa] 8.");
    let updated_jar = jar.add(auth_cookie);
    println!("\t---------------> [handle_2fa] 9.");

    Ok((updated_jar, (StatusCode::PARTIAL_CONTENT, response)))
}

#[tracing::instrument(name = "Handle No 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    println!("\t---------------> [handle_no_2fa] 1.");
    let auth_cookie = generate_auth_cookie(email).map_err(AuthApiError::UnexpectedError)?;
    println!("\t---------------> [handle_no_2fa] 2.");
    let updated_jar = jar.add(auth_cookie);
    println!("\t---------------> [handle_no_2fa] 3.");

    Ok((
        updated_jar,
        (StatusCode::OK, Json(LoginResponse::RegularAuth)),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Secret<String>,
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
