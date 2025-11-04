# smallAuth

A production-ready authentication microservice with JWT tokens, refresh tokens, RBAC, email verification, and comprehensive security features.

## Features

### 🔐 Core Authentication
- **JWT-based Authentication** - Secure token-based authentication with HS256
- **Refresh Tokens** - Long-lived tokens for seamless session extension
- **Token Revocation** - Logout functionality with token blacklisting
- **Email Verification** - Verify user email addresses with time-limited tokens
- **Password Recovery** - Secure password reset flow with email notifications

### 🛡️ Security
- **Bcrypt Password Hashing** - Industry-standard password hashing
- **Configurable Password Policies** - Enforce password strength requirements
- **Rate Limiting** - Protect against abuse (100 requests/60s per IP)
- **Brute-Force Protection** - Block IPs after failed login attempts
- **Bearer Token Validation** - Proper Authorization header format checking
- **Token Blacklist** - Prevent use of revoked tokens

### 👥 Authorization
- **Role-Based Access Control (RBAC)** - Flexible permission system
- **Many-to-Many Relationships** - Users can have multiple roles, roles can have multiple permissions
- **Admin Endpoints** - Protected administrative functions
- **Permission Middleware** - Easy-to-use permission checking

### 🌐 Frontend Integration
- **CORS Support** - Configurable cross-origin resource sharing
- **Auto-Redirect URLs** - Redirect users after login to custom URLs
- **Email Verified Status** - Track and enforce email verification

### 📧 Email Integration
- **SMTP Support** - Send verification and recovery emails
- **HTML Email Templates** - Professional-looking email notifications
- **Configurable Email Settings** - Easy SMTP configuration via environment variables

## Quick Start

### Prerequisites
- Go 1.24.5 or later
- PostgreSQL database
- SMTP server (for email functionality)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/spuentesp/smallAuth.git
cd smallAuth
```

2. Install dependencies:
```bash
go mod download
```

3. Set up environment variables (see Configuration section below)

4. Run the server:
```bash
go run cmd/server/main.go
```

The server will start on port 8080 by default.

## Configuration

All configuration is done via environment variables:

### Database Configuration
```bash
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=smallauth
```

### JWT Configuration
```bash
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRATION_HOURS=24                    # Default: 24 hours
REFRESH_TOKEN_EXPIRATION_DAYS=30           # Default: 30 days
```

### SMTP Configuration
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### Security Configuration
```bash
# Password Requirements
PASSWORD_MIN_LENGTH=8                      # Default: 8
PASSWORD_REQUIRE_UPPER=true                # Default: true
PASSWORD_REQUIRE_LOWER=true                # Default: true
PASSWORD_REQUIRE_DIGIT=true                # Default: true
PASSWORD_REQUIRE_SYMBOL=true               # Default: true

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100                # Default: 100
RATE_LIMIT_WINDOW_SECONDS=60               # Default: 60

# Brute Force Protection
BRUTE_FORCE_MAX_ATTEMPTS=5                 # Default: 5
BRUTE_FORCE_BLOCK_SECONDS=300              # Default: 300 (5 minutes)

# Password Recovery
PASSWORD_RECOVERY_TOKEN_TTL=86400          # Default: 86400 (24 hours)
```

### CORS Configuration
```bash
CORS_ALLOWED_ORIGINS=*                     # Default: * (allow all)
# or specify multiple origins:
# CORS_ALLOWED_ORIGINS=http://localhost:3000,https://myapp.com
CORS_ALLOW_CREDENTIALS=true                # Default: true
```

### Frontend Configuration
```bash
FRONTEND_BASE_URL=http://localhost:3000    # Used for email verification links
```

### Server Configuration
```bash
GIN_TRUSTED_PROXIES=127.0.0.1              # Comma-separated list of trusted proxy IPs
```

### Admin Bootstrapping (Optional)
```bash
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=SecurePassword123!
```

## API Endpoints

### Public Endpoints (No Authentication Required)

#### Register User
```http
POST /register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "recovery_email": "recovery@example.com",
  "password": "SecurePass123!"
}
```

Response:
```json
{
  "message": "user registered successfully, please check your email to verify your account"
}
```

#### Login
```http
POST /login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "base64-encoded-refresh-token",
  "redirect_url": "https://app.example.com/dashboard"
}
```

#### Validate Token
```http
POST /token/validate
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Response:
```json
{
  "valid": true,
  "claims": {
    "sub": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "exp": 1699300000
  }
}
```

#### Refresh Access Token
```http
POST /token/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

Response:
```json
{
  "token": "new-access-token",
  "refresh_token": "new-refresh-token"
}
```

#### Verify Email
```http
POST /user/verify-email
Content-Type: application/json

{
  "token": "verification-token-from-email"
}
```

Response:
```json
{
  "message": "email verified successfully"
}
```

#### Request Password Recovery
```http
POST /user/recover
Content-Type: application/json

{
  "email": "john@example.com"
}
```

Response:
```json
{
  "message": "If the email exists, recovery instructions have been sent."
}
```

#### Health Check
```http
GET /health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Authenticated Endpoints (Require Bearer Token)

All authenticated endpoints require an `Authorization` header:
```
Authorization: Bearer your-jwt-token-here
```

#### Get Current User
```http
GET /user
Authorization: Bearer your-jwt-token
```

#### Update User Profile
```http
PUT /user
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "email": "newemail@example.com",
  "recovery_email": "newrecovery@example.com",
  "auto_redirect_url": "https://myapp.com/dashboard"
}
```

#### Change Password
```http
PUT /user/password
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "old_password": "OldPass123!",
  "new_password": "NewPass123!"
}
```

#### Set Auto-Redirect URL
```http
PUT /user/auto-redirect
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "auto_redirect_url": "https://myapp.com/dashboard"
}
```

#### Resend Verification Email
```http
POST /user/resend-verification
Authorization: Bearer your-jwt-token
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer your-jwt-token
```

Response:
```json
{
  "message": "logged out successfully"
}
```

### Admin Endpoints (Require "manage_users" Permission)

#### List All Users
```http
GET /admin/users
Authorization: Bearer admin-jwt-token
```

#### Change User Roles
```http
PUT /admin/users/:id/roles
Authorization: Bearer admin-jwt-token
Content-Type: application/json

{
  "role_ids": [1, 2]
}
```

## Database Schema

### Tables

- **users** - User accounts with credentials and profile information
  - id, username, password_hash, email, email_verified, recovery_email, auto_redirect_url, timestamps

- **roles** - User roles (e.g., admin, user, moderator)
  - id, name, description

- **permissions** - Granular permissions (e.g., manage_users, view_reports)
  - id, name, description

- **user_roles** - Many-to-many relationship between users and roles
  - user_id, role_id

- **role_permissions** - Many-to-many relationship between roles and permissions
  - role_id, permission_id

- **refresh_tokens** - Long-lived tokens for session extension
  - id, user_id, token, expires_at, revoked, timestamps

- **email_verification_tokens** - Tokens for email verification
  - id, user_id, token, expires_at, timestamps

- **token_blacklist** - Revoked JWT tokens
  - id, token, expires_at, created_at

- **password_recovery_tokens** - Tokens for password reset
  - id, user_id, token, expires_at

## Architecture

### Authentication Flow

1. **Registration**
   - User submits credentials
   - Password is hashed with bcrypt
   - User created with `email_verified=false`
   - Verification email sent with 24-hour token
   - User record saved to database

2. **Email Verification**
   - User clicks link in email
   - Token validated and checked for expiration
   - `email_verified` set to true
   - Token deleted from database

3. **Login**
   - Credentials validated
   - JWT access token generated (24hr default)
   - Refresh token generated (30 days default)
   - Both tokens returned to client

4. **Access Token Refresh**
   - Client sends expired/expiring access token + refresh token
   - Refresh token validated
   - New access token generated
   - Old refresh token revoked, new one issued
   - Token rotation prevents reuse

5. **Logout**
   - Access token added to blacklist
   - All user's refresh tokens revoked
   - Client discards tokens

### Security Features

- **Password Hashing**: Bcrypt with cost factor 10
- **JWT Signing**: HS256 with configurable secret
- **Token Blacklist**: Prevents use of revoked tokens
- **Rate Limiting**: In-memory sliding window per IP
- **Brute Force Protection**: IP blocking after failed attempts
- **Email Verification**: Required for full account access
- **CORS**: Configurable allowed origins

## Development

### Running Tests
```bash
go test ./...
```

### Building
```bash
go build -o smallauth cmd/server/main.go
```

### Docker Support
```bash
docker-compose up -d
```

## Production Deployment

### Environment Setup
1. Use strong, unique JWT secrets
2. Configure production SMTP settings
3. Set appropriate CORS origins (don't use `*`)
4. Enable HTTPS
5. Configure trusted proxies
6. Set reasonable rate limits
7. Monitor token blacklist size and clean up expired entries

### Database Migrations
The application uses GORM AutoMigrate, which runs on startup. For production:
- Review migration changes before deploying
- Consider using versioned migration files
- Backup database before updates

### Monitoring
- Health check endpoint: `GET /health`
- Monitor failed login attempts
- Track token blacklist growth
- Monitor email sending failures

## API Documentation

Full OpenAPI/Swagger documentation is available in `openapi.yaml`.

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## Support

[Add support information here]
