<p align="center">
  <a href="https://magicentry.rs">
    <img alt="magicentry" height=200 src="./static/logo.svg">
  </a>
</p>

<p align="center">
  A smol identity provider
</p>

<p align="center">
  <a href="https://github.com/dzervas/magicentry/actions/workflows/test.yaml"><img src="https://img.shields.io/github/actions/workflow/status/dzervas/magicentry/test.yaml?style=flat-square" alt="Test"></a>
  <a href="https://ko-fi/dzervas"><img alt="donate" src="https://img.shields.io/badge/%24-donate-ff69b4.svg?style=flat-square"></a>
  <a href="https://github.com/dzervas/magicentry/releases/latest"><img src="https://img.shields.io/github/v/release/dzervas/magicentry?style=flat-square" alt="Release"></a>
</p>

<p align="center">
  <a href="https://ko-fi.com/dzervas"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Ko-Fi"></a>
</p>

An identity provider that focuses on passwordless authentication and simplicity.
Its target use case is for hobbyists and small organizations that need a simple
way to manage user accounts and access to web applications. The only way to
authenticate is by using magic links sent through email or using passkeys.

It has small footprint, is easy to deploy and maintain, and does not require
any other external service (like a database).

It has no admin panel by choice and the only way to dynamically alter its configuration
is by updating the configuration file or use ingress resource annotations.

## 🗄️ User Storage Options

MagicEntry supports flexible user storage to work with your existing infrastructure:

### YAML-based Users (Default)
Users are defined in configuration files - either directly in `config.yaml` or in a separate file specified by `users_file`.

```yaml
users:
  - username: admin
    email: admin@example.com
    name: Admin User
    realms: [all]
```

### SQL Database Users 
Connect MagicEntry to your existing user database without requiring schema changes. Configure any SQL query to fetch user data:

```yaml
users_sql:
  connection_string: "sqlite:users.db"  # Or PostgreSQL, MySQL, etc.
  query: >
    SELECT 
      user_id as id,
      email_address as email,
      display_name as name,
      permissions as realms
    FROM users 
    WHERE email_address = ?
```

**Requirements:** Your query must return exactly these four columns:
- `id` - Unique user identifier (used as username)
- `email` - User's email address  
- `name` - User's display name
- `realms` - User permissions/roles (JSON array or comma-separated string)

**Validations:** MagicEntry automatically validates:
- ✅ Connection string is not empty
- ✅ Query is not empty  
- ✅ Query is a SELECT statement
- ✅ Query contains all required column names (id, email, name, realms)

**Supported databases:**
- SQLite: `sqlite:path/to/database.db`
- PostgreSQL: `postgresql://user:pass@localhost/database` 
- MySQL: `mysql://user:pass@localhost/database`

**Configuration examples:**
- `config.sql.sample.yaml` - Complete example with multiple database scenarios
- `users.sample.yaml` - YAML-based user configuration

**Example queries for different schemas:**
```sql
-- Simple mapping with JSON realms
SELECT id, email, name, realms FROM app_users WHERE email = ?

-- Complex join with comma-separated roles  
SELECT 
  CAST(u.user_id AS CHAR) as id,
  u.email_address as email,
  u.full_name as name,
  GROUP_CONCAT(r.role_name) as realms
FROM users u
JOIN user_roles ur ON u.id = ur.user_id  
JOIN roles r ON ur.role_id = r.id
WHERE u.email_address = ? AND u.active = 1
GROUP BY u.id, u.email_address, u.full_name
```

Check out the documentation at [magicentry.rs](https://magicentry.rs).
