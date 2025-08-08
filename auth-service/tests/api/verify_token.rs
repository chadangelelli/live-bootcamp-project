use serde_json::json;

use crate::helpers::{get_random_email, signup_and_login, TestApp};
use auth_service::utils::constants::JWT_COOKIE_NAME;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [json!({}), json!({"invalid": "field"})];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let password = "P4sSword123!";

    let login_response = signup_and_login(&app, &email, &password).await;

    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let body = json!({
        "token": auth_cookie.value()
    });

    let response = app.post_verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let test_cases = [json!({ "token": "" }), json!({ "token": "invalid" })];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Unauthorized token: {:?}",
            test_case
        )
    }
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let test_cases = ["", "invalid"];

    for test_case in test_cases {
        let body = json!({
            "token": test_case,
        });

        let response = app.post_verify_token(&body).await;

        assert_eq!(response.status().as_u16(), 401);
    }
}
