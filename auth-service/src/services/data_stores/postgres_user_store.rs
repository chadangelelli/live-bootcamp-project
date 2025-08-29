use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, Secret};
use sqlx::{postgres::PgRow, FromRow, PgPool, Row};

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
            email: Email::parse(Secret::new(row.email)).unwrap(),
            password: Password::parse(Secret::new(row.password_hash), true).unwrap(),
            requires_2fa: row.requires_2fa,
        }
    }
}

impl<'r> FromRow<'r, PgRow> for User {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(User {
            email: Email::parse(Secret::new(row.try_get("email")?))
                .map_err(|_| sqlx::Error::RowNotFound)?,
            password: Password::parse(Secret::new(row.try_get("password_hash")?), true)
                .map_err(|_| sqlx::Error::RowNotFound)?,
            requires_2fa: row.try_get("requires_2fa")?,
        })
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.user_exists(&user.email).await {
            return Err(UserStoreError::UserAlreadyExists);
        }

        let password_hash = compute_password_hash(user.password.as_ref().clone())
            .await
            .map_err(UserStoreError::UnexpectedError)?;

        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref().expose_secret(),
            password_hash.expose_secret(),
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user_row = sqlx::query_as!(
            UserRow,
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref().expose_secret()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        Ok(User::from(user_row))
    }

    #[tracing::instrument(name = "Check if user exists in Postgres", skip_all)]
    async fn user_exists(&self, email: &Email) -> bool {
        let row = sqlx::query("SELECT 1 FROM users WHERE email = $1")
            .bind(email.as_ref().expose_secret())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError);

        match row {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        }
    }

    #[tracing::instrument(name = "Validating user credentials in Postgres", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<User, UserStoreError> {
        let user = self.get_user(email).await?;

        verify_password_hash(user.password.as_ref().clone(), password.as_ref().clone())
            .await
            .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        Ok(user)
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Secret<String>,
) -> Result<()> {
    let current_span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash.expose_secret())?;

            Argon2::default()
                .verify_password(
                    password_candidate.expose_secret().as_bytes(),
                    &expected_password_hash,
                )
                // .map_err(|e| e.into())
                .wrap_err("failed to verify password hash")
        })
    })
    .await;

    result?
}
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>> {
    let current_span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.expose_secret().as_bytes(), &salt)?
            .to_string();

            Ok(Secret::new(password_hash))
        })
    })
    .await;

    result?
}
