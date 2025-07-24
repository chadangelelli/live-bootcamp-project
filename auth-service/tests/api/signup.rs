use crate::helpers::{get_random_email, TestApp};
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