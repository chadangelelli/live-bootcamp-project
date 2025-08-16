use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.user_exists(&user.email).await {
            return Err(UserStoreError::UserAlreadyExists);
        }

        let password_hash = compute_password_hash(user.get_password().as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        // TODO: replace with query! macro
        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
            .bind(user.email.as_ref())
            .bind(password_hash)
            .bind(user.requires_2fa())
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        // TODO: Use query_as! macro for typed queries
        let user =
            sqlx::query_as("SELECT email, password_hash, requires_2fa FROM users WHERE email = $1")
                .bind(email.as_ref())
                .fetch_one(&self.pool)
                .await
                .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(user)
    }

    async fn user_exists(&self, email: &Email) -> bool {
        // TODO: replace with query! macro
        let row = sqlx::query("SELECT 1 FROM users WHERE email = $1")
            .bind(email.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError);

        match row {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        }
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        verify_password_hash(&user.get_password().as_ref(), password.as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }
}

async fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash: PasswordHash<'_> = PasswordHash::new(expected_password_hash)?;

    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| e.into())
}

async fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error>> {
    let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)?,
    )
    .hash_password(password.as_bytes(), &salt)?
    .to_string();

    Ok(password_hash)
}
