use core::panic;
use dotenvy::dotenv;
use lazy_static::lazy_static;
use secrecy::Secret;
use std::{collections::HashMap, env as std_env};

lazy_static! {
    pub static ref ENV: HashMap<String, String> = init_env();
    pub static ref DATABASE_URL: Secret<String> = ENV
        .get(env::DATABASE_URL_ENV_VAR)
        .cloned()
        .map(Secret::new)
        .unwrap_or_else(|| { panic!("DATABASE_URL must be set.") });
    pub static ref JWT_SECRET: Secret<String> = ENV
        .get(env::JWT_SECRET_ENV_VAR)
        .cloned()
        .map(Secret::new)
        .unwrap_or_else(|| { panic!("JWT_SECRET must be set.") });
    pub static ref REDIS_HOSTNAME: String = ENV
        .get(env::REDIS_HOSTNAME_ENV_VAR)
        .cloned()
        .unwrap_or(DEFAULT_REDIS_HOSTNAME.to_string());
    pub static ref POSTMARK_AUTH_TOKEN: Secret<String> = ENV
        .get(env::POSTMARK_AUTH_TOKEN_ENV_VAR)
        .cloned()
        .map(Secret::new)
        .unwrap_or_else(|| { panic!("POSTMARK_AUTH_TOKEN must be set.") });
}

fn init_env() -> HashMap<String, String> {
    dotenv().ok(); // Load environment variables
    std_env::vars().collect()
}

pub mod env {
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const REDIS_HOSTNAME_ENV_VAR: &str = "REDIS_HOSTNAME";
    pub const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";
}

pub const JWT_COOKIE_NAME: &str = "jwt";
pub const DEFAULT_REDIS_HOSTNAME: &str = "127.0.0.1";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
    pub mod email_client {
        use std::time::Duration;

        pub const BASE_URL: &str = "https://api.postmarkapp.com/email";
        // If you created your own Postmark account, make sure to use your email address!
        pub const SENDER: &str = "bogdan@codeiron.io";
        pub const TIMEOUT: Duration = std::time::Duration::from_secs(10);
    }
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
    pub mod email_client {
        use std::time::Duration;

        pub const SENDER: &str = "test@email.com";
        pub const TIMEOUT: Duration = std::time::Duration::from_millis(200);
    }
}
