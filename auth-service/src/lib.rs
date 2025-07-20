use std::error::Error;

use axum::{
    http::StatusCode, 
    response::IntoResponse, 
    routing::post, 
    serve::Serve, 
    Router
};
use tower_http::services::ServeDir;


pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind(address).await?;

        let address = listener.local_addr()?.to_string();

        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(signup_handler));

        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
 
async fn signup_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}