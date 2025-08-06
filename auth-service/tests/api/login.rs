use serde_json::json;

use crate::helpers::{get_random_email, TestApp};
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

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
        "email": "doesnt@exist.com",
        "password": "PaSSW0rD!",
    });

    let response = app.post_login(&invalid_creds).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Should be 401 for doest@exist.com"
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
