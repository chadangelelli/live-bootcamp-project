use crate::helpers::{get_random_email, TestApp};
use auth_service::routes::SignupResponse;
use serde_json::json;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "password": "password123",
            "requires2FA": true,
        }),
        json!({
            "email": get_random_email(),
        }),
        json!({
            "email": get_random_email(),
            "requires2FA": false,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(response.status().as_u16(), 422, "Failed for input: {:?}", test_case);
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let valid_input = json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": true,
    });

    let response = app.post_signup(&valid_input).await;

     let expected_response = SignupResponse {
        message: "User created successfully.".to_owned(),
    };

    assert_eq!(
        response.status().as_u16(),
        201, 
        "Failed for valid input: {:?}", valid_input
    );

    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}
