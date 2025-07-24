use auth_service::Application;
use reqwest::Client; 

pub struct TestApp {
    pub address: String, 
    pub http_client: Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await 
            .expect("[auth_service::helpers] Failed to build app!");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = Client::new();

        TestApp { address, http_client }
    }

    pub async fn get_path(&self, path: &str) -> reqwest::Response {
        self.http_client
            .get(&format!("{}", &self.address))
            .send()
            .await 
            .expect(&format!("[auth_service::TestApp] Failed to get '{}' path.", path))
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where Body: serde::Serialize, {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await 
            .expect("[auth_service::TestApp] Failed to post signup request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", uuid::Uuid::new_v4())
}