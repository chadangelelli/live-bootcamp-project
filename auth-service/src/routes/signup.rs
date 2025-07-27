use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::User};

pub async fn signup_handler(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>
) -> impl IntoResponse {
    let user =  User::new(
        request.email,
        request.password,
        request.requires_2fa,
    ); 

    let mut user_store = state.user_store.write().await;

    let user_created = user_store.add_user(user)
        .map_err(|e| {
            eprintln!("Error adding user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to add user")
        });

    if let Err(err) = user_created {
        return err.into_response();
    }

    let response = Json(SignupResponse {
        message: "User created successfully.".to_string(),
    }); 

    (StatusCode::CREATED, response).into_response()
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool, 
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}