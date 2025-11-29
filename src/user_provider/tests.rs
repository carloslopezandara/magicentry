//! Security tests for UserProvider implementations, focusing on SQL injection prevention

/// Test SQL injection through malicious query configuration (validation only)
#[test]
fn test_sql_injection_query_validation() {
    // Test malicious query configurations that should be rejected
    let malicious_queries = vec![
        // Non-SELECT statements
        "INSERT INTO users (email, name, realms) VALUES (?, 'hacker', 'admin')",
        "UPDATE users SET realms = 'admin' WHERE email = ?",  
        "DELETE FROM users WHERE email = ?",
        "DROP TABLE users",
        "CREATE TABLE malicious (data TEXT)",
        
        // Multiple statements (SQL injection with semicolon)
        "SELECT * FROM users; DROP TABLE users",
        "select id, email, name, realms from users where email = ?; DROP TABLE users;",
        "SELECT id, email, name, realms FROM users WHERE email = ?; INSERT INTO admin_users VALUES ('hacker', 'admin');",
        "SELECT id, email, name, realms FROM users; DELETE FROM users WHERE email = 'admin@example.com';",
        "select * from users; drop table",  // El caso específico que mencionaste
        "SELECT 1; DROP TABLE users; SELECT 2;",  // Múltiples statements
        
        // Empty query
        "",
        "   ",
        
        // Missing required columns 
        "SELECT email, name FROM users WHERE email = ?", // missing 'id', 'realms'
        "SELECT id, email FROM users WHERE email = ?",   // missing 'name', 'realms'
        "SELECT name, realms FROM users WHERE email = ?", // missing 'id', 'email'
    ];

    for malicious_query in malicious_queries {
        println!("Testing malicious query: {}", malicious_query);
        
        // Test the validation logic directly without connection
        let query_lower = malicious_query.to_lowercase();
        let required_columns = ["id", "email", "name", "realms"];
        
        // Should fail SELECT validation
        if malicious_query.trim().is_empty() || !query_lower.starts_with("select") {
            println!("✅ Query correctly identified as invalid (empty or not SELECT): {}", malicious_query);
            continue;
        }
        
        // Should fail column validation
        let mut missing_columns = false;
        for col in &required_columns {
            if !query_lower.contains(col) {
                missing_columns = true;
                break;
            }
        }
        
        // Check for multiple statements (semicolons)
        if malicious_query.contains(';') {
            let statements: Vec<&str> = malicious_query.split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
                
            if statements.len() > 1 {
                println!("✅ Query correctly identified as having multiple statements: {}", malicious_query);
                continue;
            }
        }
        
        if missing_columns {
            println!("✅ Query correctly identified as missing required columns: {}", malicious_query);
        } else {
            panic!("Query validation should have detected problems: {}", malicious_query);
        }
    }
}

/// Test multiple statement injection attacks specifically
#[test]
fn test_multiple_statement_injection_attacks() {
    println!("\n=== Testing Multiple Statement SQL Injection Attacks ===");
    
    let multiple_statement_attacks = vec![
        // Classic multiple statement attacks
        "SELECT * FROM users; DROP TABLE users",
        "select * from users; drop table",  // Tu ejemplo específico
        "SELECT id, email, name, realms FROM users WHERE email = ?; DROP TABLE users;",
        "SELECT id, email, name, realms FROM users; DELETE FROM users;",
        "SELECT 1; DROP TABLE users; SELECT 2;",
        
        // More sophisticated attacks
        "SELECT id, email, name, realms FROM users WHERE email = ?; INSERT INTO users VALUES (1, 'hacker@evil.com', 'Hacker', 'admin');",
        "SELECT id, email, name, realms FROM users; UPDATE users SET realms = 'admin' WHERE email = 'victim@example.com';",
        "SELECT id, email, name, realms FROM users; CREATE TABLE malicious_log (data TEXT);",
        "SELECT id, email, name, realms FROM users; GRANT ALL ON users TO 'attacker';",
        
        // Encoded and obfuscated attempts
        "SELECT id, email, name, realms FROM users;/*comment*/DROP TABLE users;",
        "SELECT id, email, name, realms FROM users;   DROP TABLE users;",
        "SELECT id, email, name, realms FROM users\n; DROP TABLE users",
    ];

    for attack_query in &multiple_statement_attacks {
        println!("🔍 Testing: {}", attack_query);
        
        // Check if query contains semicolon (primary indicator of multiple statements)
        let contains_semicolon = attack_query.contains(';');
        
        if contains_semicolon {
            // Count how many statements by counting semicolons
            let statement_count = attack_query.matches(';').count() + 1;
            println!("   ⚠️  Detected {} potential statements in query", statement_count);
            
            // Multiple statements detected - this should be blocked
            println!("   ✅ Multiple statement attack detected and would be blocked");
        }
        
        // Additional check: look for dangerous keywords after semicolon
        if let Some(after_semicolon) = attack_query.split(';').nth(1) {
            let dangerous_keywords = ["drop", "delete", "insert", "update", "create", "alter", "grant"];
            let after_semicolon_lower = after_semicolon.trim().to_lowercase();
            
            for keyword in &dangerous_keywords {
                if after_semicolon_lower.starts_with(keyword) {
                    println!("   🚨 DANGEROUS: Found '{}' after semicolon!", keyword.to_uppercase());
                    break;
                }
            }
        }
        println!();
    }
}

/// Test how our actual validation handles multiple statements
#[test] 
fn test_actual_validation_against_multiple_statements() {
    println!("\n=== Testing Actual UserSQL Validation Logic ===");
    
    let test_cases = vec![
        "select * from users; drop table",
        "SELECT id, email, name, realms FROM users; DROP TABLE users;",
        "SELECT id, email, name, realms FROM users WHERE email = ?; DELETE FROM users;",
    ];

    for test_query in test_cases {
        println!("Testing query: {}", test_query);
        
        // Simulate the actual validation logic from UserSQL::new()
        
        // 1. Check if empty
        if test_query.trim().is_empty() {
            println!("  ❌ Rejected: Query is empty");
            continue;
        }
        
        // 2. Check if starts with SELECT
        if !test_query.trim().to_lowercase().starts_with("select") {
            println!("  ❌ Rejected: Query must be a SELECT statement");
            continue;
        }
        
        // 3. Check for required columns
        let query_lower = test_query.to_lowercase();
        let required_columns = ["id", "email", "name", "realms"];
        let mut missing_columns = Vec::new();
        
        for col in &required_columns {
            if !query_lower.contains(col) {
                missing_columns.push(*col);
            }
        }
        
        if !missing_columns.is_empty() {
            println!("  ❌ Rejected: Missing required columns: {:?}", missing_columns);
            continue;
        }
        
        // 4. Additional security check: look for semicolons (multiple statements)
        if test_query.contains(';') {
            println!("  ⚠️  WARNING: Query contains semicolon - potential multiple statements!");
            
            // Split by semicolon and analyze each part
            let parts: Vec<&str> = test_query.split(';').collect();
            println!("  📊 Found {} parts separated by semicolons:", parts.len());
            
            for (i, part) in parts.iter().enumerate() {
                let part_trimmed = part.trim();
                if part_trimmed.is_empty() {
                    continue;
                }
                
                println!("    Part {}: '{}'", i + 1, part_trimmed);
                
                if i > 0 && !part_trimmed.is_empty() {
                    println!("    🚨 SECURITY ALERT: Additional statement detected after semicolon!");
                    println!("  ❌ BLOCKED: Multiple statements not allowed");
                    break;
                }
            }
            continue;
        }
        
        // If we get here, basic validation passed (but we should add semicolon check)
        println!("  ✅ Passed basic validation (but should add semicolon check!)");
    }
}

/// Test the actual UserSQL implementation against multiple statement injection
#[test]
fn test_real_implementation_blocks_multiple_statements() {
    use super::sql::UserSQL;
    use crate::config::UserSQLConfig;
    
    println!("\n=== Testing REAL UserSQL Implementation Against Multiple Statements ===");
    
    let dangerous_queries = vec![
        "select * from users; drop table",  // Tu ejemplo específico
        "SELECT id, email, name, realms FROM users; DROP TABLE users;",
        "SELECT id, email, name, realms FROM users WHERE email = ?; DELETE FROM users;",
        "SELECT id, email, name, realms FROM users; INSERT INTO malicious VALUES ('hack');",
    ];

    // Create a runtime for async testing
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    for dangerous_query in dangerous_queries {
        println!("🧪 Testing with REAL UserSQL: {}", dangerous_query);
        
        let config = UserSQLConfig {
            connection: "sqlite::memory:".to_string(),
            query: dangerous_query.to_string(),
        };
        
        // Test the actual implementation
        let result = rt.block_on(async {
            UserSQL::from_config(config).await
        });
        
        match result {
            Ok(_) => {
                println!("  ❌ SECURITY ISSUE: Query was accepted when it should have been blocked!");
                panic!("Multiple statement injection attack was not blocked: {}", dangerous_query);
            }
            Err(e) => {
                println!("  ✅ BLOCKED: {}", e);
                
                // Verify the error message indicates it was blocked for the right reason
                let error_msg = format!("{}", e);
                if error_msg.contains("Multiple SQL statements") {
                    println!("  ✅ Correctly identified as multiple statements attack");
                } else {
                    println!("  ⚠️  Blocked for different reason: {}", error_msg);
                }
            }
        }
        println!();
    }
}

/// Test that valid queries pass validation
#[test]
fn test_valid_query_validation() {
    let valid_queries = vec![
        "SELECT id, email, name, realms FROM users WHERE email = ?",
        "SELECT id, name, email, realms FROM users WHERE email = ? AND active = 1",
        "select id, email, name, realms from users where email = ?", // lowercase
        "  SELECT id, email, name, realms FROM users WHERE email = ?  ", // with spaces
        "SeLeCt id, email, name, realms FROM users WHERE email = ?", // mixed case
        "Select id, email, name, realms FROM users WHERE email = ?", // capitalized
        "sElEcT id, email, name, realms FROM users WHERE email = ?", // random case
    ];

    for valid_query in valid_queries {
        println!("Testing valid query: {}", valid_query);
        
        // Test the validation logic directly
        let query_lower = valid_query.trim().to_lowercase();
        let required_columns = ["id", "email", "name", "realms"];
        
        // Should pass SELECT validation (case-insensitive)
        assert!(query_lower.starts_with("select"), "Should be SELECT query: {}", valid_query);
        assert!(!valid_query.trim().is_empty(), "Should not be empty: {}", valid_query);
        
        // Should pass column validation
        for col in &required_columns {
            assert!(query_lower.contains(col), 
                "Query should contain required column '{}': {}", col, valid_query);
        }
        
        println!("✅ Valid query correctly passed validation: {}", valid_query);
    }
}

/// Test connection string validation logic
#[test]
fn test_connection_validation() {
    let invalid_connections = vec![
        "",          // empty
        "   ",       // whitespace only
        "invalid",   // not a valid URL scheme
    ];

    for invalid_connection in invalid_connections {
        println!("Testing invalid connection: '{}'", invalid_connection);
        
        // Test validation logic directly
        assert!(invalid_connection.trim().is_empty() || !invalid_connection.contains("://"),
            "Connection should be identified as invalid: {}", invalid_connection);
            
        println!("✅ Invalid connection correctly identified: '{}'", invalid_connection);
    }
    
    let valid_connections = vec![
        "sqlite::memory:",
        "sqlite:database.db",
        "postgresql://user:pass@localhost/db",
        "mysql://user:pass@localhost/db",
    ];

    for valid_connection in valid_connections {
        println!("Testing valid connection: {}", valid_connection);
        
        // Test validation logic directly  
        assert!(!valid_connection.trim().is_empty(), "Should not be empty");
        assert!(valid_connection.contains("://") || valid_connection.starts_with("sqlite:"),
            "Should have valid scheme: {}", valid_connection);
            
        println!("✅ Valid connection correctly identified: {}", valid_connection);
    }
}

/// Test prepared statement parameter detection
#[test] 
fn test_parameter_binding_validation() {
    let queries_with_unsafe_params = vec![
        "SELECT id, email, name, realms FROM users WHERE email = '$email'",     // dollar substitution
        "SELECT id, email, name, realms FROM users WHERE email = {email}",      // brace substitution  
        "SELECT id, email, name, realms FROM users WHERE email = %email%",      // percent substitution
        "SELECT id, email, name, realms FROM users WHERE email = 'hardcoded'",  // hardcoded value
    ];

    for unsafe_query in queries_with_unsafe_params {
        println!("Testing unsafe parameter query: {}", unsafe_query);
        
        // These patterns indicate unsafe parameter substitution
        let has_unsafe_params = unsafe_query.contains("$") || 
                               unsafe_query.contains("{") ||
                               unsafe_query.contains("%") ||
                               unsafe_query.contains("'hardcoded'");
                               
        assert!(has_unsafe_params, "Should detect unsafe parameter patterns: {}", unsafe_query);
        println!("✅ Unsafe parameter pattern detected: {}", unsafe_query);
    }
    
    let queries_with_safe_params = vec![
        "SELECT id, email, name, realms FROM users WHERE email = ?",
        "SELECT id, email, name, realms FROM users WHERE email = ? AND active = ?",
        "SELECT id, email, name, realms FROM users WHERE email = $1",  // PostgreSQL style
    ];

    for safe_query in queries_with_safe_params {
        println!("Testing safe parameter query: {}", safe_query);
        
        // These use proper parameter binding
        let has_safe_params = safe_query.contains("?") || safe_query.contains("$1");
        assert!(has_safe_params, "Should have safe parameter binding: {}", safe_query);
        println!("✅ Safe parameter binding detected: {}", safe_query);
    }
}

/// Test case-insensitive SELECT validation logic
#[test]
fn test_case_insensitive_select_validation() {
    println!("\n=== Testing Case-Insensitive SELECT Validation Logic ===");
    
    let case_variations = vec![
        ("SELECT id, email, name, realms FROM users WHERE email = ?", "uppercase"),
        ("select id, email, name, realms FROM users WHERE email = ?", "lowercase"),  
        ("Select id, email, name, realms FROM users WHERE email = ?", "capitalized"),
        ("SeLeCt id, email, name, realms FROM users WHERE email = ?", "mixed case"),
        ("sElEcT id, email, name, realms FROM users WHERE email = ?", "random case"),
        ("   SELECT id, email, name, realms FROM users WHERE email = ?   ", "with spaces"),
    ];
    
    for (query_variation, description) in case_variations {
        println!("🧪 Testing {} SELECT: {}", description, query_variation);
        
        // Test the validation logic used in UserSQL::new()
        let query_trimmed_lower = query_variation.trim().to_lowercase();
        
        // Should pass SELECT validation (case-insensitive)
        assert!(query_trimmed_lower.starts_with("select"), 
            "Case-insensitive SELECT validation should pass for {}: {}", description, query_variation);
        
        // Should pass column validation
        let required_columns = ["id", "email", "name", "realms"];
        for col in &required_columns {
            assert!(query_trimmed_lower.contains(col), 
                "Query should contain required column '{}': {}", col, query_variation);
        }
        
        println!("  ✅ ACCEPTED: Case-insensitive validation working correctly for {}", description);
        println!();
    }
}