-- Add users table for sqlite-users feature
-- This table stores user accounts that can authenticate with MagicEntry

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    realms TEXT NOT NULL,  -- JSON array of realms e.g. ["admin", "example"]
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast email lookups (primary authentication method)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Index for username lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- Sample data for testing (optional - can be removed in production)
INSERT OR IGNORE INTO users (username, email, name, realms) VALUES 
    ('admin', 'admin@example.com', 'Admin User', '["all"]'),
    ('valid', 'valid@example.com', 'Valid User', '["example"]');