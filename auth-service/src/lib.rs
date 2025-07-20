use std::error::Error;

use axum::{ routing::post, serve::Serve, Router };
use tower_http::services::ServeDir;

pub mod routes;
use crate::routes::{ 
 login_handler,
 logout_handler,
 signup_handler,
 verify_2fa_handler,
 verify_token_handler,
};

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
            .route("/login", post(login_handler))
            .route("/logout", post(logout_handler))
            .route("/signup", post(signup_handler))
            .route("/verify_2fa", post(verify_2fa_handler))
            .route("/verify_token", post(verify_token_handler));

        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}