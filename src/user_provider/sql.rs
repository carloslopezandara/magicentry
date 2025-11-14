use async_trait::async_trait;
use sqlx::{AnyPool, Row};
use serde_json;
use crate::user::User;
use crate::user_provider::UserProvider;
use crate::error::AppError;

/// SQL-based user provider - reads users from any SQL database
/// Supports configurable connection strings and queries for SQLite, PostgreSQL, MySQL, etc.
pub struct UserSQL {
    pool: AnyPool,
    query: String,
}

impl UserSQL {
    /// Create a new SQL user provider
    /// Supports SQLite, PostgreSQL, MySQL and other databases via connection string
    pub async fn new(connection: &str, query: String) -> Result<Self, AppError> {
        // Validate connection string
        if connection.trim().is_empty() {
            return Err(AppError::from(anyhow::anyhow!("Connection string cannot be empty")));
        }

        // Validate query
        if query.trim().is_empty() {
            return Err(AppError::from(anyhow::anyhow!("SQL query cannot be empty")));
        }

        // Basic SQL validation - should start with SELECT
        if !query.trim().to_lowercase().starts_with("select") {
            return Err(AppError::from(anyhow::anyhow!("Query must be a SELECT statement")));
        }

        // Required columns validation
        let query_lower = query.to_lowercase();
        let required_columns = ["id", "email", "name", "realms"];
        for col in &required_columns {
            if !query_lower.contains(col) {
                return Err(AppError::from(anyhow::anyhow!(
                    "Query must return '{}' column (use 'column_name as {}' to map)",
                    col, col
                )));
            }
        }

        let pool = AnyPool::connect(connection).await
            .map_err(|e| AppError::from(anyhow::anyhow!("Failed to connect to SQL database: {}", e)))?;
        
        Ok(Self { pool, query })
    }

    /// Execute the configured query and map results to User struct
    async fn execute_query(&self, where_clause: Option<(&str, &str)>) -> Result<Vec<User>, AppError> {
        let mut full_query = self.query.clone();
        
        // Add WHERE clause if provided (for email lookups)
        if let Some((field, _value)) = where_clause {
            if full_query.to_lowercase().contains("where") {
                full_query = format!("{} AND {} = ?", full_query, field);
            } else {
                full_query = format!("{} WHERE {} = ?", full_query, field);
            }
        }
        
        let mut query_builder = sqlx::query(&full_query);
        
        // Bind the parameter if we have a WHERE clause
        if let Some((_, value)) = where_clause {
            query_builder = query_builder.bind(value);
        }
        
        let rows = query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::from(anyhow::anyhow!("SQL query failed: {}", e)))?;
        
        let mut users = Vec::new();
        
        for row in rows {
            // The user's query should return exactly these column aliases:
            // - id: unique identifier (used as username)
            // - email: user's email address  
            // - name: user's display name
            // - realms: user permissions/roles (JSON array or comma-separated)
            
            let id: String = row.try_get("id")
                .map_err(|e| AppError::from(anyhow::anyhow!("Query must return 'id' column: {}", e)))?;
            
            let email: String = row.try_get("email")
                .map_err(|e| AppError::from(anyhow::anyhow!("Query must return 'email' column: {}", e)))?;
            
            let name: String = row.try_get("name")
                .map_err(|e| AppError::from(anyhow::anyhow!("Query must return 'name' column: {}", e)))?;
            
            // Handle realms - could be JSON string or comma-separated values
            let realms: Vec<String> = match row.try_get::<String, _>("realms") {
                Ok(realms_str) => {
                    // Try to parse as JSON array first
                    match serde_json::from_str::<Vec<String>>(&realms_str) {
                        Ok(json_realms) => json_realms,
                        Err(_) => {
                            // If not JSON, treat as comma-separated string
                            realms_str.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        }
                    }
                }
                Err(_) => {
                    // Default to empty realms if column doesn't exist
                    vec![]
                }
            };
            
            users.push(User {
                email,
                username: id, // Use id as username
                name,
                realms,
            });
        }
        
        Ok(users)
    }
}

#[async_trait]
impl UserProvider for UserSQL {
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let users = self.execute_query(Some(("email", email))).await?;
        Ok(users.into_iter().next())
    }
    
    async fn list_all_users(&self) -> Result<Vec<User>, AppError> {
        self.execute_query(None).await
    }
}