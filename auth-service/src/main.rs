use std::sync::Arc;
use tokio::sync::RwLock;

use auth_service::{
    app_state::AppState,
    services::{
        hashmap_user_store::HashmapUserStore, hashset_banned_token_store::HashSetBannedTokenStore,
        HashmapTwoFACodeStore,
    },
    utils::constants::prod,
    Application,
};

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(auth_service::services::mock_email_client::MockEmailClient);
    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("[auth_service::main] Failed to build app!");

    app.run()
        .await
        .expect("[auth_service::main] Failed to run app!")
}
