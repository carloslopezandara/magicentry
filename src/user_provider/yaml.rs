use async_trait::async_trait;
use crate::user::User;
use crate::user_provider::UserProvider;
use crate::error::AppError;
use crate::config::LiveConfig;

/// YAML-based user provider - reads users from configuration files
/// This maintains compatibility with the existing YAML-based user system
pub struct UserYAML {
    users: Vec<User>,
}

impl UserYAML {
    /// Create a new YAML user provider from configuration
    pub fn new(config: &LiveConfig) -> Self {
        Self {
            users: config.users.clone(),
        }
    }
}

#[async_trait]
impl UserProvider for UserYAML {
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        Ok(self.users
            .iter()
            .find(|u| u.email == email)
            .cloned())
    }
    
    async fn list_all_users(&self) -> Result<Vec<User>, AppError> {
        Ok(self.users.clone())
    }
}