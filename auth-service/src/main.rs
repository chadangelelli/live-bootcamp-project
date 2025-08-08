use std::sync::Arc;
use tokio::sync::RwLock;

use auth_service::{
    app_state::AppState, services::hashmap_user_store::HashmapUserStore,
    services::hashset_banned_token_store::HashSetBannedTokenStore, utils::constants::prod,
    Application,
};

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
    let app_state = AppState::new(user_store, banned_token_store);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("[auth_service::main] Failed to build app!");

    app.run()
        .await
        .expect("[auth_service::main] Failed to run app!")
}
