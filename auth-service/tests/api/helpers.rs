use std::sync::Arc;

use reqwest::{cookie::Jar, Client};
use serde_json::json;
use tokio::sync::RwLock;

use auth_service::{
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
    domain::{LoginAttemptId, TwoFACode},
    services::{
        hashmap_user_store::HashmapUserStore, mock_email_client::MockEmailClient,
        HashSetBannedTokenStore, HashmapTwoFACodeStore,
    },
    utils::constants::test,
    Application,
};

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(MockEmailClient);

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client,
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("[auth_service::helpers] Failed to build app!");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());

        let http_client = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        TestApp {
            address,
            cookie_jar,
            http_client,
            banned_token_store,
            two_fa_code_store,
        }
    }

    pub async fn get_path(&self, path: &str) -> reqwest::Response {
        self.http_client
            .get(&format!("{}", &self.address))
            .send()
            .await
            .expect(&format!(
                "[auth_service::TestApp] Failed to get '{}' path.",
                path
            ))
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("[auth_service::TestApp] Failed to post signup request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute login request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute logout request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", uuid::Uuid::new_v4())
}

pub async fn signup(
    app: &TestApp,
    email: &str,
    password: &str,
    require_2fa: bool,
) -> reqwest::Response {
    let signup_body = json!({
        "email": &email,
        "password": &password,
        "requires2FA": require_2fa,
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);
    signup_response
}

pub async fn login(
    app: &TestApp,
    email: &str,
    password: &str,
    require_2fa: bool,
) -> reqwest::Response {
    let login_body = json!({
        "email": &email,
        "password": &password,
    });
    let success_status_code = if require_2fa { 206 } else { 200 };
    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), success_status_code);
    login_response
}

pub async fn signup_and_login(app: &TestApp, email: &str, password: &str) -> reqwest::Response {
    signup(app, email, password, false).await;
    login(app, email, password, false).await
}

pub fn get_random_login_attempt_id() -> String {
    format!("{}", LoginAttemptId::generate_random().as_ref())
}

pub fn get_random_two_fa_code() -> String {
    format!("{}", TwoFACode::generate_random().as_ref())
}
