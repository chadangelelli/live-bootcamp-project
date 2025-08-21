use argon2::{
    password_hash::{self, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use sqlx::{postgres::PgRow, FromRow, PgPool, Row};
use std::error::Error;

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

pub struct UserRow {
    email: String,
    password_hash: String,
    requires_2fa: bool,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            email: Email::parse(row.email).unwrap(),
            password: Password::parse(row.password_hash, true).unwrap(),
            requires_2fa: row.requires_2fa,
        }
    }
}

impl<'r> FromRow<'r, PgRow> for User {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(User {
            email: Email::parse(row.try_get("email")?).map_err(|_| sqlx::Error::RowNotFound)?,
            password: Password::parse(row.try_get("password_hash")?, true)
                .map_err(|_| sqlx::Error::RowNotFound)?,
            requires_2fa: row.try_get("requires_2fa")?,
        })
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.user_exists(&user.email).await {
            return Err(UserStoreError::UserAlreadyExists);
        }

        let password_hash = compute_password_hash(user.password.as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        // TODO: replace with query! macro
        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
            .bind(user.email.as_ref())
            .bind(password_hash)
            .bind(user.requires_2fa)
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        /*
        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;
             */

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        // TODO: replace with UserRow and query_as! macro
        let user: User =
            sqlx::query_as("SELECT email, password_hash, requires_2fa FROM users WHERE email = $1")
                .bind(email.as_ref())
                .fetch_one(&self.pool)
                .await
                .map_err(|_| UserStoreError::UserNotFound)?;

        /*
        let user_row = sqlx::query_as!(
            UserRow,
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(User::from(user_row))
         */
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
    ) -> Result<User, UserStoreError> {
        let user = self.get_user(email).await?;

        verify_password_hash(user.password.as_ref(), password.as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(user)
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
