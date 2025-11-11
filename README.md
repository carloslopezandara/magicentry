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

MagicEntry supports two ways to manage user accounts:

### YAML-based Users (Default)
Users are defined in configuration files - either directly in `config.yaml` or in a separate file specified by `users_file`.

```yaml
users:
  - username: admin
    email: admin@example.com
    name: Admin User
    realms: [all]
```

### SQLite-based Users (Feature: `sqlite-users`)
Users are stored in the SQLite database for dynamic management. Enable this feature at compile time:

```bash
# Build with SQLite users support
cargo build --features sqlite-users

# Configure to use SQLite storage
users_file: "sqlite"
```

When `users_file: "sqlite"` is set and the `sqlite-users` feature is enabled, MagicEntry will read users from the `users` table in the SQLite database instead of YAML files. This provides a more dynamic approach for user management while maintaining read-only access for authentication purposes.

**Configuration examples:**
- `config.sqlite-users.yaml` - Example configuration for testing SQLite users
- `config.production-sqlite.yaml` - Production-ready template based on config.sample.yaml

**Populating users in SQLite:**
```sql
INSERT INTO users (username, email, name, realms) VALUES 
    ('admin', 'admin@example.com', 'Admin User', '["all"]'),
    ('user', 'user@example.com', 'Regular User', '["example"]');
```

Check out the documentation at [magicentry.rs](https://magicentry.rs).
