use dotenvy::dotenv;
use lazy_static::lazy_static;
use std::{collections::HashMap, env as std_env};

lazy_static! {
    pub static ref ENV: HashMap<String, String> = init_env();
    pub static ref DATABASE_URL: String = ENV
        .get(env::DATABASE_URL_ENV_VAR)
        .cloned()
        .unwrap_or_else(|| { panic!("DATABASE_URL must be set.") });
    pub static ref JWT_SECRET: String = ENV
        .get(env::JWT_SECRET_ENV_VAR)
        .cloned()
        .unwrap_or_else(|| { panic!("JWT_SECRET must be set.") });
}

fn init_env() -> HashMap<String, String> {
    dotenv().ok(); // Load environment variables
    std_env::vars().collect()
}

pub mod env {
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}
