use async_trait::async_trait;
use crate::user::User;
use crate::error::AppError;

pub mod yaml;
pub mod sql;

#[cfg(test)]
pub mod tests;

pub use yaml::UserYAML;
pub use sql::UserSQL;
pub use crate::database_abstraction::DatabaseType;

/// Trait for providing user data from different sources (YAML, SQL, etc.)
/// This allows MagicEntry to read users from the client's existing database
/// without forcing a specific schema or structure.
#[async_trait]
pub trait UserProvider: Send + Sync {
    /// Get a user by email address (primary authentication method)
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    
    /// Get all users (useful for debugging/admin purposes)
    async fn list_all_users(&self) -> Result<Vec<User>, AppError>;
    
    /// Check if a user exists by email
    async fn user_exists(&self, email: &str) -> Result<bool, AppError> {
        Ok(self.get_user_by_email(email).await?.is_some())
    }
}