use auth_service::domain::{Email, LoginAttemptId, TwoFACode};
use auth_service::utils::JWT_COOKIE_NAME;
use secrecy::{ExposeSecret, Secret};
use serde_json::json;
use wiremock::{
    matchers::{method, path},
    Mock, ResponseTemplate,
};

use crate::helpers;
use crate::helpers::{
    get_random_email, get_random_login_attempt_id, get_random_two_fa_code, TestApp,
};
use auth_service::{routes::TwoFactorAuthResponse, ErrorResponse};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let test_cases = ["".to_string(), "{".to_string()];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": "",
            "loginAttemptId": "hello",
            "2FACode": "not-a-uuid"

        }),
        json!({
            "email": "test@example.com",
            "loginAttemptId": get_random_login_attempt_id(),
            "2FACode": "invalid",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": "invalid",
            "2FACode": get_random_two_fa_code(),
        }),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

/*
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;
    let email = get_random_email();
    let password = "PA5Sw0Rd!";

    helpers::signup(&app, &email, password, true).await;

    let login_response = helpers::login(&app, &email, password, true).await;
    let login_response_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to deserialize login response");

    assert_eq!(login_response_body.message, "2FA required".to_owned());
    assert!(!login_response_body.login_attempt_id.is_empty());

    let login_attempt_id = login_response_body.login_attempt_id;
    let two_fa_code = {
        let two_fa_code_store = app.two_fa_code_store.read().await;
        let tuple = two_fa_code_store
            .get_code(&Email::parse(Secret::new(email.clone())).unwrap())
            .await
            .expect("Failed to get 2FA code");
        tuple.1.as_ref().expose_secret().clone()
    };

    let bad_email = get_random_email();
    let bad_login_attempt_id = get_random_login_attempt_id();
    let bad_two_fa_code = get_random_two_fa_code();

    let test_cases = [
        json!({
            "email": bad_email,
            "loginAttemptId": bad_login_attempt_id,
            "2FACode": bad_two_fa_code,
        }),
        json!({
            "email": email,
            "loginAttemptId": bad_login_attempt_id,
            "2FACode": two_fa_code,
        }),
        json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": bad_two_fa_code,
        }),
    ];

    for payload in test_cases {
        let response = app.post_verify_2fa(&payload).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            payload
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }

    app.clean_up().await;
}
 */

//TODO: fix should_return_401_if_incorrect_credentials
/*
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // --------------------------

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let login_attempt_id = response_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let two_fa_code = code_tuple.1.as_ref();

    // --------------------------

    let incorrect_email = get_random_email();
    let incorrect_login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let incorrect_two_fa_code = TwoFACode::default().as_ref().to_owned();

    let test_cases = vec![
        (
            incorrect_email.as_str(),
            login_attempt_id.as_str(),
            two_fa_code.expose_secret().as_str(),
        ),
        (
            random_email.as_str(),
            incorrect_login_attempt_id.expose_secret(),
            two_fa_code.expose_secret().as_str(),
        ),
        (
            random_email.as_str(),
            login_attempt_id.as_str(),
            incorrect_two_fa_code.expose_secret().as_str(),
        ),
    ];

    for (email, login_attempt_id, code) in test_cases {
        let request_body = serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": code
        });

        let response = app.post_verify_2fa(&request_body).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            request_body
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }

    app.clean_up().await;
}
  */

/*
/// Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.
#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;
    let email = get_random_email();
    let password = "PA5Sw0Rd!";

    helpers::signup(&app, &email, password, true).await;

    let login_response = helpers::login(&app, &email, password, true).await;

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let login_response_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to deserialize login response");

    assert_eq!(login_response_body.message, "2FA required".to_owned());
    assert!(!&login_response_body.login_attempt_id.is_empty());

    let login_attempt_id = login_response_body.login_attempt_id;
    let two_fa_code = {
        let two_fa_code_store = app.two_fa_code_store.read().await;
        let tuple = two_fa_code_store
            .get_code(&Email::parse(Secret::new(email.clone())).unwrap())
            .await
            .expect("Failed to get 2FA code");
        tuple.1.as_ref().expose_secret().clone()
    };

    let payload = json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": two_fa_code,
    });

    // 200 first try
    let response1 = app.post_verify_2fa(&payload).await;
    assert_eq!(response1.status().as_u16(), 200);
    let auth_cookie = response1
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    // 401 second try
    let response2 = app.post_verify_2fa(&payload).await;
    assert_eq!(response2.status().as_u16(), 401);
    let auth_cookie = response1
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}
 */

// TODO: fix should_return_401_if_old_code
/*
#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    // First login call

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let login_attempt_id = response_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let code = code_tuple.1.as_ref();

    // Second login call

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    // 2FA attempt with old login_attempt_id and code

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code.expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}
  */
