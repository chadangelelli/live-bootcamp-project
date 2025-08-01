use std::sync::Arc;
use tokio::sync::RwLock;

use auth_service::Application;
use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(
        HashmapUserStore::default()
    ));
    let app_state = AppState::new(user_store);

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await 
        .expect("[auth_service::main] Failed to build app!");

    app.run().await.expect("[auth_service::main] Failed to run app!")
}
