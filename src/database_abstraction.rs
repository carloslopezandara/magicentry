//! Database Abstraction Layer
//! 
//! This module provides database-agnostic operations for MagicEntry.
//! It handles differences between SQLite, PostgreSQL, and MySQL.

use sqlx::{AnyPool, Row};
use anyhow::Context;
use crate::error::AppError;

#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    SQLite,
    PostgreSQL,  
    MySQL,
}

impl DatabaseType {
    /// Detect database type from connection string
    pub fn from_connection_string(connection: &str) -> Self {
        if connection.starts_with("sqlite:") || connection.starts_with("file:") {
            Self::SQLite
        } else if connection.starts_with("postgres:") || connection.starts_with("postgresql:") {
            Self::PostgreSQL
        } else if connection.starts_with("mysql:") || connection.starts_with("mariadb:") {
            Self::MySQL
        } else {
            // Default to SQLite for backward compatibility
            Self::SQLite
        }
    }

    /// Get parameter placeholder for this database type
    pub fn parameter(&self, index: usize) -> String {
        match self {
            Self::SQLite | Self::MySQL => "?".to_string(),
            Self::PostgreSQL => format!("${}", index + 1),
        }
    }

    /// Get the parameter placeholder style for this database type
    pub fn parameter_style(&self) -> &'static str {
        match self {
            Self::SQLite | Self::MySQL => "?",
            Self::PostgreSQL => "$1", // PostgreSQL uses $1, $2, etc.
        }
    }
    
    /// Check if parameter pattern in query matches expected style for this database
    pub fn validate_parameter_style(&self, query: &str) -> Result<(), String> {
        let has_question_mark = query.contains('?');
        let has_dollar_param = query.contains('$');
        
        // Check for mixed parameter styles - this is dangerous and should be rejected
        if has_question_mark && has_dollar_param {
            return Err("Mixed parameter styles detected (both '?' and '$' parameters). \
                       Use only one parameter style per query for security.".to_string());
        }
        
        match self {
            Self::PostgreSQL => {
                if has_question_mark && !has_dollar_param {
                    return Err("PostgreSQL queries should use $1, $2, etc. parameters, but found '?' parameters. \
                         Consider updating your query to use PostgreSQL parameter style.".to_string());
                }
                
                // Additional validation for PostgreSQL: check parameter numbering
                if has_dollar_param {
                    use regex::Regex;
                    let re = Regex::new(r"\$(\d+)").unwrap();
                    let mut param_numbers: Vec<usize> = re.captures_iter(query)
                        .filter_map(|cap| cap.get(1))
                        .filter_map(|m| m.as_str().parse().ok())
                        .collect();
                    param_numbers.sort();
                    param_numbers.dedup();
                    
                    // Check if parameters start from $1 and are sequential
                    for (i, &param_num) in param_numbers.iter().enumerate() {
                        if param_num != i + 1 {
                            return Err(format!(
                                "PostgreSQL parameters must be sequential starting from $1. Found parameter ${} but expected ${}.",
                                param_num, i + 1
                            ));
                        }
                    }
                }
            }
            Self::SQLite | Self::MySQL => {
                if has_dollar_param && !has_question_mark {
                    return Err("SQLite/MySQL queries should use '?' parameters, but found $1-style parameters. \
                         Consider updating your query to use '?' parameter style.".to_string());
                }
            }
        }
        
        Ok(())
    }

    /// Get current timestamp function for this database type
    pub fn now_function(&self) -> &'static str {
        match self {
            Self::SQLite => "datetime('now')",
            Self::PostgreSQL => "NOW()",
            Self::MySQL => "NOW()",
        }
    }

    /// Get UPSERT syntax for config_kv table
    pub fn upsert_config_syntax(&self) -> String {
        match self {
            Self::SQLite => format!(
                "INSERT INTO config_kv (key, value) VALUES ({}, {}) ON CONFLICT(key) DO UPDATE SET value = {}, updated_at = {}",
                self.parameter(0),
                self.parameter(1), 
                self.parameter(2),
                self.now_function()
            ),
            Self::PostgreSQL => format!(
                "INSERT INTO config_kv (key, value) VALUES ({}, {}) ON CONFLICT(key) DO UPDATE SET value = {}, updated_at = {}",
                self.parameter(0),
                self.parameter(1),
                self.parameter(2), 
                self.now_function()
            ),
            Self::MySQL => format!(
                "INSERT INTO config_kv (key, value) VALUES ({}, {}) ON DUPLICATE KEY UPDATE value = {}, updated_at = {}",
                self.parameter(0),
                self.parameter(1),
                self.parameter(2),
                self.now_function()
            ),
        }
    }

    /// Fix user column name (PostgreSQL has 'user' as reserved word)
    pub fn user_column(&self) -> &'static str {
        match self {
            Self::PostgreSQL => "user_data", // Rename to avoid reserved word
            _ => "user",
        }
    }
}

/// Database abstraction wrapper
#[derive(Debug)]
pub struct DatabaseAbstraction {
    pub pool: AnyPool,
    pub db_type: DatabaseType,
}

impl DatabaseAbstraction {
    /// Create new database abstraction from connection string
    pub async fn new(connection_string: &str) -> Result<Self, AppError> {
        let db_type = DatabaseType::from_connection_string(connection_string);
        let pool = AnyPool::connect(connection_string)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { pool, db_type })
    }

    /// Insert passkey with database-specific syntax
    pub async fn insert_passkey(&self, user_data: &str, passkey_data: &str) -> Result<(), AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "INSERT INTO passkeys (user_data, passkey_data) VALUES (?, ?)"
            }
            DatabaseType::PostgreSQL => {
                "INSERT INTO passkeys (user_data, passkey_data) VALUES ($1, $2)"
            }
        };

        sqlx::query(query)
            .bind(user_data)
            .bind(passkey_data)
            .execute(&self.pool)
            .await
            .context("Failed to insert passkey")?;

        Ok(())
    }

    /// Get passkeys for user with database-specific syntax
    pub async fn get_passkeys_for_user(&self, user_str: &str) -> Result<Vec<(i64, String, String)>, AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "SELECT id, user_data, passkey_data FROM passkeys WHERE user_data = ?"
            }
            DatabaseType::PostgreSQL => {
                "SELECT id, user_data, passkey_data FROM passkeys WHERE user_data = $1"
            }
        };

        let rows = sqlx::query(query)
            .bind(user_str)
            .fetch_all(&self.pool)
            .await
            .context("Failed to get passkeys")?;

        let mut results = Vec::new();
        for row in rows {
            let id: i64 = row.try_get(0).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get id: {}", e)))?;
            let user_data: String = row.try_get(1).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get user_data: {}", e)))?;
            let passkey_data: String = row.try_get(2).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get passkey_data: {}", e)))?;
            results.push((id, user_data, passkey_data));
        }

        Ok(results)
    }

    /// Upsert config value with database-specific syntax
    pub async fn upsert_config(&self, key: &str, value: &str) -> Result<(), AppError> {
        let query = self.db_type.upsert_config_syntax();

        sqlx::query(&query)
            .bind(key)
            .bind(value)
            .bind(value) // For the UPDATE part
            .execute(&self.pool)
            .await
            .context("Failed to upsert config")?;

        Ok(())
    }

    /// Get config value with database-specific syntax
    pub async fn get_config(&self, key: &str) -> Result<Option<String>, AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "SELECT value FROM config_kv WHERE key = ?"
            }
            DatabaseType::PostgreSQL => {
                "SELECT value FROM config_kv WHERE key = $1"
            }
        };

        let row = sqlx::query(query)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get config")?;

        if let Some(row) = row {
            let value: String = row.try_get(0).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get config value: {}", e)))?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Delete config value with database-specific syntax
    pub async fn delete_config(&self, key: &str) -> Result<(), AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "DELETE FROM config_kv WHERE key = ?"
            }
            DatabaseType::PostgreSQL => {
                "DELETE FROM config_kv WHERE key = $1"
            }
        };

        sqlx::query(query)
            .bind(key)
            .execute(&self.pool)
            .await
            .context("Failed to delete config")?;

        Ok(())
    }

    /// Insert user secret with database-specific syntax
    pub async fn insert_user_secret(
        &self, 
        code: &str, 
        user: &str, 
        metadata: &str, 
        expires_at: &str
    ) -> Result<(), AppError> {
        let user_col = self.db_type.user_column();
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                format!("INSERT INTO user_secrets (code, {}, metadata, expires_at) VALUES (?, ?, ?, ?)", user_col)
            }
            DatabaseType::PostgreSQL => {
                format!("INSERT INTO user_secrets (code, {}, metadata, expires_at) VALUES ($1, $2, $3, $4)", user_col)
            }
        };

        sqlx::query(&query)
            .bind(code)
            .bind(user)
            .bind(metadata)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .context("Failed to insert user secret")?;

        Ok(())
    }

    /// Get user secret with expiry check
    pub async fn get_user_secret(&self, code: &str) -> Result<Option<(String, String, String, String, String)>, AppError> {
        let user_col = self.db_type.user_column();
        let now_func = self.db_type.now_function();
        
        let query = match self.db_type {
            DatabaseType::SQLite => {
                format!("SELECT code, {}, expires_at, created_at, metadata FROM user_secrets WHERE code = ? AND expires_at > {}", user_col, now_func)
            }
            DatabaseType::PostgreSQL => {
                format!("SELECT code, {}, expires_at, created_at, metadata FROM user_secrets WHERE code = $1 AND expires_at > {}", user_col, now_func)
            }
            DatabaseType::MySQL => {
                format!("SELECT code, {}, expires_at, created_at, metadata FROM user_secrets WHERE code = ? AND expires_at > {}", user_col, now_func)
            }
        };

        let row = sqlx::query(&query)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get user secret")?;

        if let Some(row) = row {
            let code: String = row.try_get(0).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get code: {}", e)))?;
            let user: String = row.try_get(1).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get user: {}", e)))?;
            let expires_at: String = row.try_get(2).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get expires_at: {}", e)))?;
            let created_at: String = row.try_get(3).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get created_at: {}", e)))?;
            let metadata: String = row.try_get(4).map_err(|e| AppError::from(anyhow::anyhow!("Failed to get metadata: {}", e)))?;
            Ok(Some((code, user, expires_at, created_at, metadata)))
        } else {
            Ok(None)
        }
    }

    /// Count user secrets
    pub async fn count_user_secrets(&self, code: &str) -> Result<i64, AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "SELECT COUNT(*) FROM user_secrets WHERE code = ?"
            }
            DatabaseType::PostgreSQL => {
                "SELECT COUNT(*) FROM user_secrets WHERE code = $1"
            }
        };

        let count: i64 = sqlx::query_scalar(query)
            .bind(code)
            .fetch_one(&self.pool)
            .await
            .context("Failed to count user secrets")?;

        Ok(count)
    }

    /// Delete user secret
    pub async fn delete_user_secret(&self, code: &str) -> Result<(), AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "DELETE FROM user_secrets WHERE code = ?"
            }
            DatabaseType::PostgreSQL => {
                "DELETE FROM user_secrets WHERE code = $1"
            }
        };

        sqlx::query(query)
            .bind(code)
            .execute(&self.pool)
            .await
            .context("Failed to delete user secret")?;

        Ok(())
    }

    /// Clean up expired secrets
    pub async fn cleanup_expired_secrets(&self, now: &str) -> Result<(), AppError> {
        let query = match self.db_type {
            DatabaseType::SQLite | DatabaseType::MySQL => {
                "DELETE FROM user_secrets WHERE expires_at <= ?"
            }
            DatabaseType::PostgreSQL => {
                "DELETE FROM user_secrets WHERE expires_at <= $1"
            }
        };

        sqlx::query(query)
            .bind(now)
            .execute(&self.pool)
            .await
            .context("Failed to cleanup expired secrets")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_type_detection() {
        assert_eq!(DatabaseType::from_connection_string("sqlite:test.db"), DatabaseType::SQLite);
        assert_eq!(DatabaseType::from_connection_string("postgresql://user:pass@localhost/db"), DatabaseType::PostgreSQL);
        assert_eq!(DatabaseType::from_connection_string("mysql://user:pass@localhost/db"), DatabaseType::MySQL);
        assert_eq!(DatabaseType::from_connection_string("unknown://test"), DatabaseType::SQLite); // default fallback
    }

    #[test]
    fn test_parameter_generation() {
        assert_eq!(DatabaseType::SQLite.parameter(0), "?");
        assert_eq!(DatabaseType::SQLite.parameter(1), "?");
        
        assert_eq!(DatabaseType::PostgreSQL.parameter(0), "$1");
        assert_eq!(DatabaseType::PostgreSQL.parameter(1), "$2");
        assert_eq!(DatabaseType::PostgreSQL.parameter(2), "$3");
        
        assert_eq!(DatabaseType::MySQL.parameter(0), "?");
    }

    #[test]
    fn test_now_functions() {
        assert_eq!(DatabaseType::SQLite.now_function(), "datetime('now')");
        assert_eq!(DatabaseType::PostgreSQL.now_function(), "NOW()");
        assert_eq!(DatabaseType::MySQL.now_function(), "NOW()");
    }

    #[test]
    fn test_user_column() {
        assert_eq!(DatabaseType::SQLite.user_column(), "user");
        assert_eq!(DatabaseType::PostgreSQL.user_column(), "user_data");
        assert_eq!(DatabaseType::MySQL.user_column(), "user");
    }
}