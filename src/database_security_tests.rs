//! SQL injection and security tests for database abstraction layer
//! Tests the security validations without requiring actual database connections

#[cfg(test)]
mod database_security_tests {
    use crate::user_provider::UserSQL;

    /// Test malicious query configurations are rejected during UserSQL creation
    #[tokio::test]
    async fn test_sql_injection_prevention() {
        println!("\n🛡️ TESTING: SQL Injection Prevention in UserSQL Configuration");
        
        let db_url = "postgresql://postgres:password@localhost:5433/magicentry_test";
        
        // Test malicious query configurations that should be rejected
        let malicious_queries = vec![
            // SQL Injection attempts - the specific case you mentioned
            ("DROP table attempt", "SELECT id, email, name, realms FROM users; DROP TABLE users"),
            ("Classic injection", "SELECT * FROM users; DROP TABLE users"),
            ("Multiple statements", "SELECT id, email, name, realms FROM users WHERE email = $1; DELETE FROM users"),
            ("INSERT injection", "INSERT INTO users (email) VALUES ('hacker'); SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Update injection", "UPDATE users SET realms = 'admin'; SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Delete injection", "DELETE FROM users; SELECT id, email, name, realms FROM users WHERE email = $1"),
            
            // Non-SELECT statements
            ("Pure INSERT", "INSERT INTO users (email, name, realms) VALUES ($1, 'hacker', 'admin')"),
            ("Pure UPDATE", "UPDATE users SET realms = 'admin' WHERE email = $1"),
            ("Pure DELETE", "DELETE FROM users WHERE email = $1"),
            ("Pure DROP", "DROP TABLE users"),
            ("Create table", "CREATE TABLE malicious (data TEXT)"),
            ("ALTER table", "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT true"),
            ("TRUNCATE table", "TRUNCATE TABLE users"),
            
            // Advanced SQL injection techniques
            ("Union injection", "SELECT id, email, name, realms FROM users UNION SELECT 'admin' as id, 'admin@evil.com' as email, 'Admin' as name, 'admin' as realms FROM users WHERE email = $1"),
            ("Subquery injection", "SELECT id, email, name, realms FROM users WHERE email = $1 OR (SELECT COUNT(*) FROM users) > 0"),
            ("Nested statements", "SELECT id, email, name, realms FROM users WHERE email = $1; (SELECT version(); DROP TABLE users)"),
            ("Comment bypass", "SELECT id, email, name, realms FROM users /* comment */; DROP TABLE users"),
            ("Case manipulation", "select id, email, name, realms from users; DROP table users"),
            ("Multiple semicolons", "SELECT id, email, name, realms FROM users;;; DROP TABLE users"),
            
            // Database-specific attacks
            ("PostgreSQL copy", "COPY users TO '/tmp/users.csv'; SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("MySQL outfile", "SELECT id, email, name, realms FROM users INTO OUTFILE '/tmp/users.txt' WHERE email = $1"),
            ("SQLite attach", "ATTACH DATABASE '/tmp/evil.db' AS evil; SELECT id, email, name, realms FROM users WHERE email = $1"),
            
            // Function and procedure calls
            ("Function call", "SELECT version(); SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Stored procedure", "CALL evil_procedure(); SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("PostgreSQL function", "SELECT pg_sleep(10); SELECT id, email, name, realms FROM users WHERE email = $1"),
            
            // Schema manipulation
            ("Show tables", "SHOW TABLES; SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Describe table", "DESCRIBE users; SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Information schema", "SELECT table_name FROM information_schema.tables; SELECT id, email, name, realms FROM users WHERE email = $1"),
            
            // Missing required columns
            ("Missing id column", "SELECT email, name, realms FROM users WHERE email = $1"),
            ("Missing email column", "SELECT id, name, realms FROM users WHERE email = $1"),
            ("Missing name column", "SELECT id, email, realms FROM users WHERE email = $1"),
            ("Missing realms column", "SELECT id, email, name FROM users WHERE email = $1"),
            ("Only one column", "SELECT email FROM users WHERE email = $1"),
            ("Wrong column names", "SELECT user_id as id, user_email, user_name, user_realms FROM users WHERE email = $1"), // missing 'as' mappings
            
            // Empty/invalid queries
            ("Empty query", ""),
            ("Whitespace only", "   "),
            ("Comment only", "-- This is just a comment"),
            ("Newline only", "\n"),
            ("Tab only", "\t"),
            
            // Edge cases
            ("Base64 encoded", "SELECT id, email, name, realms FROM users; --RFJPUCBUQUJMRSB1c2Vycw== (DROP TABLE users in base64)"),
        ];

        for (test_name, malicious_query) in malicious_queries {
            println!("\n🚨 Testing: {}", test_name);
            println!("   Query: {}", malicious_query);
            
            // Use validation-only method that doesn't require database connection
            let result = UserSQL::validate_query(malicious_query);
            
            match result {
                Ok(_) => {
                    panic!("❌ SECURITY FAILURE: Malicious query '{}' was accepted! This should have been rejected.", test_name);
                }
                Err(error) => {
                    println!("✅ Security validation working: {}", error);
                    // Verify error message is informative
                    let error_str = error.to_string();
                    assert!(
                        error_str.contains("Query must") ||
                        error_str.contains("not allowed") ||
                        error_str.contains("Multiple statements") ||
                        error_str.contains("must return") ||
                        error_str.contains("Parameter style") ||
                        error_str.contains("SELECT") ||
                        error_str.contains("cannot be empty") ||
                        error_str.contains("Dangerous keyword"),
                        "Error message should be informative: {}", error
                    );
                }
            }
        }
        
        println!("\n🎉 ALL SQL INJECTION TESTS PASSED - Validation is secure!");
    }

    /// Test parameter style validation
    #[tokio::test]
    async fn test_parameter_style_validation() {
        println!("\n🔍 TESTING: Parameter Style Validation");
        
        let db_url = "postgresql://postgres:password@localhost:5433/magicentry_test";
        
        // Test wrong parameter styles that should be rejected
        let wrong_parameter_queries = vec![
            ("SQLite style in PostgreSQL", "SELECT id, email, name, realms FROM users WHERE email = ?"),
            ("Mixed parameters", "SELECT id, email, name, realms FROM users WHERE email = ? AND id = $1"),
            ("Wrong PostgreSQL numbering", "SELECT id, email, name, realms FROM users WHERE email = $2"), // Should start with $1
        ];

        for (test_name, wrong_query) in wrong_parameter_queries {
            println!("\n🚨 Testing: {}", test_name);
            println!("   Query: {}", wrong_query);
            
            let result = UserSQL::validate_query_for_database_type(wrong_query, "postgresql");
            
            match result {
                Ok(_) => {
                    panic!("❌ PARAMETER VALIDATION FAILURE: Wrong parameter style '{}' was accepted!", test_name);
                }
                Err(error) => {
                    println!("✅ Parameter validation working: {}", error);
                    let error_str = error.to_string();
                    assert!(
                        error_str.contains("Parameter style") ||
                        error_str.contains("PostgreSQL") ||
                        error_str.contains("$1"),
                        "Error should mention parameter style: {}", error
                    );
                }
            }
        }
        
        println!("\n🎉 PARAMETER VALIDATION TESTS PASSED!");
    }

    /// Test that valid queries are accepted (even if connection fails)
    #[tokio::test]
    async fn test_valid_queries_accepted() {
        println!("\n✅ TESTING: Valid Queries Are Accepted");
        
        let db_url = "postgresql://postgres:password@localhost:5433/magicentry_test";
        
        // Test valid queries that should pass validation (connection might fail, but that's OK)
        let valid_queries = vec![
            ("Simple valid query", "SELECT id, email, name, realms FROM users WHERE email = $1"),
            ("Case insensitive SELECT", "select id, email, name, realms from users where email = $1"),
            ("Mixed case SELECT", "Select id, email, name, realms From users Where email = $1"),
            ("With joins", "SELECT u.id, u.email, u.name, u.realms FROM users u WHERE u.email = $1"),
            ("With extra columns", "SELECT id, email, name, realms, created_at, active FROM users WHERE email = $1"),
            ("With semicolon at end", "SELECT id, email, name, realms FROM users WHERE email = $1;"),
            ("With multiple spaces", "SELECT    id,   email,   name,   realms   FROM   users   WHERE   email = $1"),
            ("With SQL keywords as strings", "SELECT 'DROP TABLE users' as id, email, name, realms FROM users WHERE email = $1"),
        ];

        for (test_name, valid_query) in valid_queries {
            println!("\n✅ Testing: {}", test_name);
            println!("   Query: {}", valid_query);
            
            let result = UserSQL::validate_query_for_database_type(valid_query, "postgresql");
            
            match result {
                Ok(_) => {
                    println!("✅ Valid query accepted successfully");
                }
                Err(error) => {
                    panic!("❌ VALIDATION FAILURE: Valid query '{}' was rejected: {}", test_name, error);
                }
            }
        }
        
        println!("\n🎉 VALID QUERY TESTS PASSED!");
    }

    /// Test security validations across different database types
    #[tokio::test]
    async fn test_security_across_database_types() {
        println!("\n🌐 TESTING: Security Validations Across Database Types");
        
        let test_cases = vec![
            ("PostgreSQL", "$1"),
            ("SQLite", "?"),
            ("MySQL", "?"),
        ];

        for (db_type, correct_param) in test_cases {
            println!("\n🔍 Testing {} security validations", db_type);
            
            // Test SQL injection prevention for this database type
            let injection_query = format!("SELECT id, email, name, realms FROM users; DROP TABLE users WHERE email = {}", correct_param);
            
            println!("   Testing injection for {}: {}", db_type, injection_query);
            
            let result = UserSQL::validate_query(&injection_query);
            match result {
                Ok(_) => panic!("❌ {} allowed SQL injection!", db_type),
                Err(error) => {
                    println!("✅ {} correctly prevented injection: {}", db_type, error);
                    assert!(error.to_string().contains("Multiple") || error.to_string().contains("statements"));
                }
            }
            
            // Test valid query for this database type  
            let valid_query = format!("SELECT id, email, name, realms FROM users WHERE email = {}", correct_param);
            println!("   Testing valid query for {}: {}", db_type, valid_query);
            
            let db_type_str = match db_type {
                "PostgreSQL" => "postgresql",
                "SQLite" => "sqlite", 
                "MySQL" => "mysql",
                _ => "sqlite",
            };
            let valid_result = UserSQL::validate_query_for_database_type(&valid_query, db_type_str);
            match valid_result {
                Ok(_) => println!("✅ {} accepted valid query", db_type),
                Err(e) => {
                    panic!("❌ {} rejected valid query: {}", db_type, e);
                }
            }
        }
        
        println!("✅ All database types correctly implement security validations");
    }
}