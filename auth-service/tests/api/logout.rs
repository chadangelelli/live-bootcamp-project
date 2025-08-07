use reqwest::Url;

use crate::helpers::{get_random_email, signup_and_login, TestApp};
use auth_service::utils::constants::JWT_COOKIE_NAME;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400, "Should be 400");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 401, "Should be 401");
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let password = "P4sSword123!";

    signup_and_login(&app, &email, &password).await;

    let logout_response = app.post_logout().await;
    assert_eq!(logout_response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let password = "P4sSword123!";

    signup_and_login(&app, &email, &password).await;

    let logout_response1 = app.post_logout().await;
    assert_eq!(logout_response1.status().as_u16(), 200);

    let logout_response2 = app.post_logout().await;
    assert_eq!(logout_response2.status().as_u16(), 400);
}
