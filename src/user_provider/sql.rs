use async_trait::async_trait;
use sqlx::{AnyPool, Row};
use serde_json;
use crate::user::User;
use crate::user_provider::UserProvider;
use crate::database_abstraction::DatabaseType;
use crate::error::AppError;

/// SQL-based user provider - reads users from any SQL database
/// Supports configurable connection strings and queries for SQLite, PostgreSQL, MySQL, etc.
#[derive(Debug)]
pub struct UserSQL {
    pool: AnyPool,
    query: String,
    db_type: DatabaseType,
}

impl UserSQL {
    /// Create a new SQL user provider
    /// Supports SQLite, PostgreSQL, MySQL and other databases via connection string
    pub async fn new(connection: &str, query: String) -> Result<Self, AppError> {
        // Validate connection string
        if connection.trim().is_empty() {
            return Err(AppError::from(anyhow::anyhow!("Connection string cannot be empty")));
        }

        // Detect database type from connection string
        let db_type = DatabaseType::from_connection_string(connection);
        println!("🔍 Detected database type: {:?} from connection: {}", db_type, connection);
        
        // Validate query
        if query.trim().is_empty() {
            return Err(AppError::from(anyhow::anyhow!("SQL query cannot be empty")));
        }

        // Basic SQL validation - should start with SELECT (case-insensitive)
        let query_trimmed_lower = query.trim().to_lowercase();
        if !query_trimmed_lower.starts_with("select") {
            return Err(AppError::from(anyhow::anyhow!("Query must be a SELECT statement")));
        }
        
        // Validate parameter style for detected database type
        if let Err(param_error) = db_type.validate_parameter_style(&query) {
            return Err(AppError::from(anyhow::anyhow!("Parameter style mismatch: {}", param_error)));
        }

        // SECURITY: Check for multiple statements (SQL injection prevention)
        if query.contains(';') {
            // Split by semicolon and check if there are multiple non-empty statements
            let statements: Vec<&str> = query.split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
                
            if statements.len() > 1 {
                return Err(AppError::from(anyhow::anyhow!(
                    "Multiple SQL statements not allowed. Found {} statements separated by semicolons.", 
                    statements.len()
                )));
            }
        }

        // Required columns validation
        let query_lower = query_trimmed_lower; // Reuse the already lowercased query
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
        
        Ok(Self { pool, query, db_type })
    }

    /// Create a new SQL user provider from config
    pub async fn from_config(config: crate::config::UserSQLConfig) -> Result<Self, AppError> {
        Self::new(&config.connection, config.query).await
    }

    /// Execute the configured query and map results to User struct
    async fn execute_query(&self, where_clause: Option<(&str, &str)>) -> Result<Vec<User>, AppError> {
        let mut full_query = self.query.clone();
        
        // Add WHERE clause if provided (for email lookups)
        if let Some((field, _value)) = where_clause {
            let param_placeholder = self.db_type.parameter(0);
            
            if full_query.to_lowercase().contains("where") {
                full_query = format!("{} AND {} = {}", full_query, field, param_placeholder);
            } else {
                full_query = format!("{} WHERE {} = {}", full_query, field, param_placeholder);
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

    /// Validate a SQL query for security issues without requiring a database connection
    pub fn validate_query(query: &str) -> Result<(), AppError> {
        // Validate query is not empty
        if query.trim().is_empty() {
            return Err(AppError::from(anyhow::anyhow!("SQL query cannot be empty")));
        }

        // Basic SQL validation - should start with SELECT (case-insensitive)
        let query_trimmed = query.trim();
        let query_trimmed_lower = query_trimmed.to_lowercase();
        
        if !query_trimmed_lower.starts_with("select") {
            return Err(AppError::from(anyhow::anyhow!("Query must be a SELECT statement")));
        }

        // SECURITY: Check for multiple statements (SQL injection prevention)
        if query.contains(';') {
            // Split by semicolon and check if there are multiple non-empty statements
            let statements: Vec<&str> = query.split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
                
            if statements.len() > 1 {
                return Err(AppError::from(anyhow::anyhow!(
                    "Multiple SQL statements not allowed. Found {} statements separated by semicolons.", 
                    statements.len()
                )));
            }
        }

        // SECURITY: Check for UNION attacks (SQL injection prevention)
        if query_trimmed_lower.contains(" union ") || 
           query_trimmed_lower.contains("union all") ||
           query_trimmed_lower.contains("union select") {
            return Err(AppError::from(anyhow::anyhow!(
                "UNION statements not allowed in user queries for security reasons"
            )));
        }

        // SECURITY: Check for dangerous SQL keywords and MySQL-specific attacks
        let dangerous_keywords = [
            "into outfile", "into dumpfile", "load data", "copy", "bulk insert",
            "xp_cmdshell", "sp_executesql", "openrowset", "opendatasource",
            "exec ", "execute ", "eval(", "sp_oa", "fn_","table("
        ];
        
        for keyword in dangerous_keywords.iter() {
            if query_trimmed_lower.contains(keyword) {
                return Err(AppError::from(anyhow::anyhow!(
                    "Dangerous keyword '{}' not allowed in user queries for security reasons", keyword
                )));
            }
        }

        // SECURITY: Check for nested SELECT statements that could be malicious
        let select_count = query_trimmed_lower.matches("select").count();
        if select_count > 1 {
            // Allow JOINs but disallow subqueries in WHERE clauses
            if query_trimmed_lower.contains("where") && query_trimmed_lower.contains(") >") {
                return Err(AppError::from(anyhow::anyhow!(
                    "Subqueries in WHERE clauses not allowed for security reasons"
                )));
            }
            // Additional check for subqueries in WHERE clause
            if query_trimmed_lower.contains("where") {
                let where_part = query_trimmed_lower.split("where").nth(1).unwrap_or("");
                if where_part.contains("select") {
                    return Err(AppError::from(anyhow::anyhow!(
                        "Subqueries in WHERE clauses not allowed for security reasons"
                    )));
                }
            }
        }

        // Required columns validation - must be in SELECT clause
        let required_columns = ["id", "email", "name", "realms"];
        
        // Extract the SELECT clause
        let select_start = query_trimmed_lower.find("select");
        let from_start = query_trimmed_lower.find("from");
        
        if let (Some(sel_pos), Some(from_pos)) = (select_start, from_start) {
            if sel_pos < from_pos {
                // Extract the column list between SELECT and FROM
                let columns_part = &query_trimmed_lower[(sel_pos + 6)..from_pos];
                
                for col in &required_columns {
                    // Check if column appears in SELECT clause (direct, with table prefix, or as alias)
                    // Look for patterns like:
                    // - "column_name as col" or "table.column_name as col" (alias)
                    // - "col" or "table.col" (direct)
                    let col_pattern_1 = format!(" as {}", col); // "column_name as id"
                    let col_pattern_2 = format!(" as {},", col); // "column_name as id," 
                    let col_pattern_3 = format!(",{},", col); // ",id,"
                    let col_pattern_4 = format!(",{} ", col); // ",id "
                    let col_pattern_5 = format!(" {} ", col); // " id "
                    let col_pattern_6 = format!(" {},", col); // " id,"
                    let col_pattern_7 = format!(".{}", col); // "u.id", "table.email"
                    let col_pattern_8 = format!(".{},", col); // "u.id,", "table.email,"
                    let col_pattern_9 = format!(".{} ", col); // "u.id ", "table.email "
                    
                    let has_alias = columns_part.contains(&col_pattern_1) || columns_part.contains(&col_pattern_2);
                    let has_direct = columns_part.contains(&col_pattern_3) || columns_part.contains(&col_pattern_4) ||
                                   columns_part.contains(&col_pattern_5) || columns_part.contains(&col_pattern_6) ||
                                   columns_part.starts_with(&format!("{},", col)) || columns_part.starts_with(&format!("{} ", col));
                    let has_table_prefix = columns_part.contains(&col_pattern_7) || columns_part.contains(&col_pattern_8) ||
                                         columns_part.contains(&col_pattern_9);
                    
                    if !has_alias && !has_direct && !has_table_prefix {
                        return Err(AppError::from(anyhow::anyhow!(
                            "Query must return '{}' column (use 'column_name as {}' to map)",
                            col, col
                        )));
                    }
                }
            }
        } else {
            // If we can't parse SELECT/FROM structure, this is an invalid query
            return Err(AppError::from(anyhow::anyhow!(
                "Invalid query structure: could not identify SELECT and FROM clauses"
            )));
        }

        Ok(())
    }

    /// Validate a SQL query for a specific database type
    pub fn validate_query_for_database_type(query: &str, db_type_str: &str) -> Result<(), AppError> {
        // First run basic validation
        Self::validate_query(query)?;

        // Detect database type
        let db_type = match db_type_str.to_lowercase().as_str() {
            "sqlite" => DatabaseType::SQLite,
            "postgresql" | "postgres" => DatabaseType::PostgreSQL,
            "mysql" => DatabaseType::MySQL,
            _ => return Err(AppError::from(anyhow::anyhow!("Unsupported database type: {}", db_type_str))),
        };

        // Validate parameter style for detected database type
        if let Err(param_error) = db_type.validate_parameter_style(query) {
            return Err(AppError::from(anyhow::anyhow!("Parameter style mismatch: {}", param_error)));
        }

        Ok(())
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