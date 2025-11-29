//! Simple test to verify database abstraction functionality

#[cfg(test)]
mod simple_tests {
    use crate::database_abstraction::DatabaseType;

    #[test]
    fn test_database_type_detection() {
        // Test SQLite detection
        assert_eq!(
            DatabaseType::from_connection_string("sqlite:test.db"),
            DatabaseType::SQLite
        );
        
        // Test PostgreSQL detection
        assert_eq!(
            DatabaseType::from_connection_string("postgresql://user:pass@localhost/db"),
            DatabaseType::PostgreSQL
        );
        
        // Test MySQL detection
        assert_eq!(
            DatabaseType::from_connection_string("mysql://user:pass@localhost/db"),
            DatabaseType::MySQL
        );
        
        println!("✅ Database type detection works correctly!");
    }

    #[test]
    fn test_parameter_generation() {
        // Test SQLite parameters
        let sqlite = DatabaseType::SQLite;
        assert_eq!(sqlite.parameter(0), "?");
        assert_eq!(sqlite.parameter(1), "?");
        
        // Test PostgreSQL parameters
        let postgres = DatabaseType::PostgreSQL;
        assert_eq!(postgres.parameter(0), "$1");
        assert_eq!(postgres.parameter(1), "$2");
        assert_eq!(postgres.parameter(2), "$3");
        
        // Test MySQL parameters
        let mysql = DatabaseType::MySQL;
        assert_eq!(mysql.parameter(0), "?");
        assert_eq!(mysql.parameter(1), "?");
        
        println!("✅ Parameter generation works correctly!");
    }

    #[test]
    fn test_parameter_style_validation() {
        // Test PostgreSQL validation
        let postgres = DatabaseType::PostgreSQL;
        
        // Should accept PostgreSQL style
        assert!(postgres.validate_parameter_style("SELECT * FROM users WHERE id = $1").is_ok());
        
        // Should reject SQLite style for PostgreSQL
        assert!(postgres.validate_parameter_style("SELECT * FROM users WHERE id = ?").is_err());
        
        // Test SQLite validation
        let sqlite = DatabaseType::SQLite;
        
        // Should accept SQLite style
        assert!(sqlite.validate_parameter_style("SELECT * FROM users WHERE id = ?").is_ok());
        
        // Should reject PostgreSQL style for SQLite
        assert!(sqlite.validate_parameter_style("SELECT * FROM users WHERE id = $1").is_err());
        
        println!("✅ Parameter style validation works correctly!");
    }

    #[test]
    fn test_now_functions() {
        assert_eq!(DatabaseType::SQLite.now_function(), "datetime('now')");
        assert_eq!(DatabaseType::PostgreSQL.now_function(), "NOW()");
        assert_eq!(DatabaseType::MySQL.now_function(), "NOW()");
        
        println!("✅ NOW function mapping works correctly!");
    }

    #[test]
    fn test_upsert_syntax_generation() {
        // Test SQLite UPSERT
        let sqlite = DatabaseType::SQLite;
        let sqlite_upsert = sqlite.upsert_config_syntax();
        assert!(sqlite_upsert.contains("ON CONFLICT"));
        assert!(sqlite_upsert.contains("datetime('now')"));
        
        // Test PostgreSQL UPSERT
        let postgres = DatabaseType::PostgreSQL;
        let postgres_upsert = postgres.upsert_config_syntax();
        assert!(postgres_upsert.contains("ON CONFLICT"));
        assert!(postgres_upsert.contains("NOW()"));
        assert!(postgres_upsert.contains("$1"));
        
        // Test MySQL UPSERT
        let mysql = DatabaseType::MySQL;
        let mysql_upsert = mysql.upsert_config_syntax();
        assert!(mysql_upsert.contains("ON DUPLICATE KEY"));
        assert!(mysql_upsert.contains("NOW()"));
        
        println!("✅ UPSERT syntax generation works correctly!");
        println!("   SQLite: {}", sqlite_upsert);
        println!("   PostgreSQL: {}", postgres_upsert);
        println!("   MySQL: {}", mysql_upsert);
    }

    #[test]
    fn test_user_column_handling() {
        // SQLite and MySQL should use 'user'
        assert_eq!(DatabaseType::SQLite.user_column(), "user");
        assert_eq!(DatabaseType::MySQL.user_column(), "user");
        
        // PostgreSQL should use 'user_data' to avoid reserved word
        assert_eq!(DatabaseType::PostgreSQL.user_column(), "user_data");
        
        println!("✅ User column handling works correctly!");
    }
}