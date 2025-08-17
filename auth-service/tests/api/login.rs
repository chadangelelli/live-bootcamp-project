use serde_json::json;

use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let test_cases = [get_random_email(), "P4SS!W0rd".to_string(), "".to_string()];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

/// Call the log-in route with incorrect credentials and assert
/// that a 401 HTTP status code is returned along with the appropriate error message.
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let invalid_creds = json!({
        "email": "doesnot@exist.com",
        "password": "PaSSW0rD!",
    });

    let response = app.post_login(&invalid_creds).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Should be 401 for doesnot@exist.com"
    );
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "P4sSword123!";

    let signup_body = serde_json::json!({
        "email": &random_email,
        "password": &password,
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": &random_email,
        "password": &password,
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "P4sSword123!";

    let signup_body = serde_json::json!({
        "email": &random_email,
        "password": &password,
        "requires2FA": true,
    });

    let signup_response = app.post_signup(&signup_body).await;

    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": &random_email,
        "password": &password,
    });

    let login_response = app.post_login(&login_body).await;

    assert_eq!(login_response.status().as_u16(), 206);

    let json_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response body as JSON.");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(random_email.clone()).unwrap();
    let lock = app.two_fa_code_store.read().await;
    let (login_attempt_id, code) = lock.get_code(&email).await.unwrap();

    assert_eq!(login_attempt_id.as_ref().len(), 36);
    assert!(!login_attempt_id.as_ref().is_empty());
    assert!(!code.as_ref().is_empty());
}
