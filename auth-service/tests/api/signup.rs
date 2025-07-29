use serde_json::json;

use crate::helpers::{get_random_email, TestApp};
use auth_service::{routes::SignupResponse, ErrorResponse};

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

/// The signup route should return a 400 HTTP status code if an invalid input is sent.
/// The input is considered invalid if:
/// - The email is empty or does not contain '@'
/// - The password is less than 8 characters
/// Create an array of invalid inputs. Then, iterate through the array and 
/// make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let input = [
        json!({
            "email": "",
            "password": "password123",
            "requires2FA": true,
        }),
        json!({
            "email": "invalid-email",
            "password": "password123",
            "requires2FA": true,
        }),
        json!({
            "email": get_random_email(),
            "password": "short",
            "requires2FA": true,
        }),
    ];  

    let app = TestApp::new().await;

    for i in input.iter() {
        let response = app.post_signup(i).await;

        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", i);

                assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

/// Call the signup route twice (w/ valid input). 
/// The second request should fail with a 409 HTTP status code    
#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    let valid_input = json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": true,
    });

    // First signup should succeed
    let response = app.post_signup(&valid_input).await;
    assert_eq!(response.status().as_u16(), 201);

    // Second signup with the same email should fail
    let response = app.post_signup(&valid_input).await;
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );  
}
