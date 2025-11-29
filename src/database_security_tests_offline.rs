//! SQL injection and security tests for database abstraction layer
//! Tests the security validations WITHOUT requiring actual database connections

#[cfg(test)]
mod database_security_tests_offline {
    use crate::user_provider::UserSQL;

    /// Test malicious query configurations are rejected during UserSQL validation
    #[tokio::test]
    async fn test_sql_injection_prevention_offline() {
        println!("\n🛡️ TESTING: SQL Injection Prevention (Offline Mode)");
        
        // Test malicious query configurations that should be rejected at validation level
        let malicious_queries = vec![
            // SQL Injection attempts - the specific case you mentioned
            ("DROP table attempt", "SELECT id, email, name, realms FROM users; DROP TABLE users"),
            ("Classic injection", "SELECT * FROM users; DROP TABLE users"),
            ("Multiple statements", "SELECT id, email, name, realms FROM users WHERE email = ?; DELETE FROM users"),
            ("INSERT injection", "INSERT INTO users (email) VALUES ('hacker'); SELECT id, email, name, realms FROM users WHERE email = ?"),
            ("Update injection", "UPDATE users SET realms = 'admin'; SELECT id, email, name, realms FROM users WHERE email = ?"),
            ("Delete injection", "DELETE FROM users; SELECT id, email, name, realms FROM users WHERE email = ?"),
            
            // Non-SELECT statements
            ("Pure INSERT", "INSERT INTO users (email, name, realms) VALUES (?, 'hacker', 'admin')"),
            ("Pure UPDATE", "UPDATE users SET realms = 'admin' WHERE email = ?"),
            ("Pure DELETE", "DELETE FROM users WHERE email = ?"),
            ("Pure DROP", "DROP TABLE users"),
            ("Create table", "CREATE TABLE malicious (data TEXT)"),
            ("ALTER table", "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT true"),
            ("TRUNCATE table", "TRUNCATE TABLE users"),
            
            // Advanced SQL injection techniques
            ("Union injection", "SELECT id, email, name, realms FROM users UNION SELECT 'admin' as id, 'admin@evil.com' as email, 'Admin' as name, 'admin' as realms FROM users WHERE email = ?"),
            ("Subquery injection", "SELECT id, email, name, realms FROM users WHERE email = ? OR (SELECT COUNT(*) FROM users) > 0"),
            ("Comment bypass", "SELECT id, email, name, realms FROM users /* comment */; DROP TABLE users"),
            ("Case manipulation", "select id, email, name, realms from users; DROP table users"),
            
            // Function and procedure calls
            ("Function call", "SELECT version(); SELECT id, email, name, realms FROM users WHERE email = ?"),
            ("Stored procedure", "CALL evil_procedure(); SELECT id, email, name, realms FROM users WHERE email = ?"),
        ];

        println!("🔍 Testing {} malicious query patterns...", malicious_queries.len());
        
        let mut passed_tests = 0;
        let mut failed_tests = 0;
        
        for (test_name, malicious_query) in malicious_queries {
            println!("\n🚨 Testing: {}", test_name);
            println!("   Query: {}", malicious_query);
            
            // Test the validation logic directly without database connection
            let validation_result = UserSQL::validate_query(malicious_query);
            
            match validation_result {
                Ok(_) => {
                    println!("❌ SECURITY FAILURE: Malicious query '{}' was accepted!", test_name);
                    failed_tests += 1;
                }
                Err(error) => {
                    println!("✅ Security validation working: {}", error);
                    passed_tests += 1;
                    
                    // Verify error message is informative
                    let error_str = error.to_string();
                    assert!(
                        error_str.contains("Query must") ||
                        error_str.contains("not allowed") ||
                        error_str.contains("Multiple statements") ||
                        error_str.contains("SELECT"),
                        "Error message should be descriptive: {}", error_str
                    );
                }
            }
        }
        
        println!("\n📊 SECURITY TEST RESULTS:");
        println!("   ✅ Passed: {}", passed_tests);
        println!("   ❌ Failed: {}", failed_tests);
        println!("   📈 Success Rate: {:.1}%", (passed_tests as f32 / (passed_tests + failed_tests) as f32) * 100.0);
        
        assert_eq!(failed_tests, 0, "All malicious queries should be rejected");
    }

    /// Test that valid queries are accepted
    #[tokio::test]
    async fn test_valid_queries_accepted_offline() {
        println!("\n✅ TESTING: Valid Queries Are Accepted (Offline Mode)");
        
        let valid_queries = vec![
            ("Simple valid query", "SELECT id, email, name, realms FROM users WHERE email = ?"),
            ("Query with multiple conditions", "SELECT id, email, name, realms FROM users WHERE email = ? AND active = true"),
            ("Query with ORDER BY", "SELECT id, email, name, realms FROM users WHERE email = ? ORDER BY created_at DESC"),
            ("Query with LIMIT", "SELECT id, email, name, realms FROM users WHERE email = ? LIMIT 1"),
            ("Query with JOIN", "SELECT u.id, u.email, u.name, u.realms FROM users u JOIN user_roles ur ON u.id = ur.user_id WHERE u.email = ?"),
        ];

        let mut passed_tests = 0;
        let mut failed_tests = 0;
        
        for (test_name, valid_query) in valid_queries {
            println!("\n✅ Testing: {}", test_name);
            println!("   Query: {}", valid_query);
            
            let validation_result = UserSQL::validate_query(valid_query);
            
            match validation_result {
                Ok(_) => {
                    println!("✅ Valid query accepted: {}", test_name);
                    passed_tests += 1;
                }
                Err(error) => {
                    println!("❌ Valid query rejected: {} - {}", test_name, error);
                    failed_tests += 1;
                }
            }
        }
        
        println!("\n📊 VALID QUERY TEST RESULTS:");
        println!("   ✅ Passed: {}", passed_tests);
        println!("   ❌ Failed: {}", failed_tests);
        
        assert_eq!(failed_tests, 0, "All valid queries should be accepted");
    }

    /// Test parameter style validation
    #[tokio::test]
    async fn test_parameter_style_validation_offline() {
        println!("\n🔍 TESTING: Parameter Style Validation (Offline Mode)");
        
        // Test SQLite style parameters (?) 
        let sqlite_query = "SELECT id, email, name, realms FROM users WHERE email = ?";
        println!("🔍 Testing SQLite parameter style: {}", sqlite_query);
        
        let result = UserSQL::validate_query_for_database_type(sqlite_query, "sqlite");
        match result {
            Ok(_) => println!("✅ SQLite parameter style accepted for SQLite"),
            Err(e) => panic!("❌ SQLite parameter style should be accepted for SQLite: {}", e),
        }
        
        // Test PostgreSQL style parameters ($1, $2)
        let pg_query = "SELECT id, email, name, realms FROM users WHERE email = $1";
        println!("🔍 Testing PostgreSQL parameter style: {}", pg_query);
        
        let result = UserSQL::validate_query_for_database_type(pg_query, "postgresql");
        match result {
            Ok(_) => println!("✅ PostgreSQL parameter style accepted for PostgreSQL"),
            Err(e) => panic!("❌ PostgreSQL parameter style should be accepted for PostgreSQL: {}", e),
        }
        
        // Test mismatched parameters (SQLite style in PostgreSQL)
        println!("🔍 Testing parameter style mismatch (SQLite style in PostgreSQL)");
        let result = UserSQL::validate_query_for_database_type(sqlite_query, "postgresql");
        match result {
            Ok(_) => panic!("❌ Parameter style mismatch should be rejected"),
            Err(e) => {
                println!("✅ Parameter style mismatch correctly rejected: {}", e);
                assert!(e.to_string().contains("Parameter style"), "Error should mention parameter style");
            }
        }
        
        println!("✅ All parameter style validations working correctly");
    }

    /// Test comprehensive security validations 
    #[tokio::test]
    async fn test_comprehensive_security_offline() {
        println!("\n🛡️ TESTING: Comprehensive Security Validations (Offline Mode)");
        
        // Test the specific attack you mentioned: "SELECT * FROM users; DROP TABLE"
        let your_specific_attack = "SELECT * FROM users; DROP TABLE users";
        println!("🚨 Testing your specific attack: {}", your_specific_attack);
        
        let result = UserSQL::validate_query(your_specific_attack);
        match result {
            Ok(_) => panic!("❌ CRITICAL: Your specific SQL injection attack was not blocked!"),
            Err(e) => {
                println!("✅ SECURITY SUCCESS: Attack blocked - {}", e);
                assert!(e.to_string().contains("Multiple") || e.to_string().contains("statements"), 
                       "Should detect multiple statements");
            }
        }
        
        // Test various forms of the attack
        let attack_variations = vec![
            "SELECT * FROM users;DROP TABLE users",
            "SELECT * FROM users ; DROP TABLE users ",
            "select * from users; drop table users",
            "SELECT * FROM users;\nDROP TABLE users",
            "SELECT * FROM users;\tDROP TABLE users",
        ];
        
        for attack in attack_variations {
            println!("🚨 Testing attack variation: {}", attack.replace('\n', "\\n").replace('\t', "\\t"));
            let result = UserSQL::validate_query(attack);
            match result {
                Ok(_) => panic!("❌ CRITICAL: SQL injection attack variation was not blocked!"),
                Err(_) => println!("✅ Attack variation blocked"),
            }
        }
        
        println!("✅ ALL SECURITY VALIDATIONS PASSED - System is protected against SQL injection!");
    }
}