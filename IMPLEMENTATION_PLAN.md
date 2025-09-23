# Small Auth Microservice with RBAC: Implementation Plan

## 1. Project Setup
- Initialize a new project (**Go** recommended for performance and simplicity)
- Set up version control (Git)
- Configure environment variables for secrets and DB connection
- Structure code following SOLID and DRY principles
- Use idiomatic Go practices (project layout, error handling, naming)
- Use frameworks/libraries to ease development:
  - Gin (HTTP routing)
  - GORM (ORM for PostgreSQL)
  - go-redis (optional, for rate limiting/brute-force protection)
  - jwt-go (JWT handling)
  - validator (input validation)
  - logrus/zap (structured logging)

## 2. Database Design
- Choose a database (PostgreSQL recommended)
- Design tables:
  - `users`: id, username, password_hash, email, recovery_email, created_at, updated_at, auto_redirect_url (optional)
  - `roles`: id, name, description
  - `user_roles`: user_id, role_id
  - `permissions`: id, name, description
  - `role_permissions`: role_id, permission_id
- Ensure admin role exists in the roles table

## 3. RBAC Logic
- Implement role-based access control middleware in Go
- Ensure RBAC logic is modular and reusable (SOLID)
- Map endpoints to required permissions

## 4. Authentication & Security
- Use secure password hashing (bcrypt or argon2)
- Implement JWT-based authentication
- Add rate limiting and input validation
- Implement brute-force protection:
  - Add exponential backoff or temporary blocking for repeated failed login attempts
  - Track failed attempts per IP and/or username
  - Return generic error messages to avoid user enumeration
- Secure endpoints with HTTPS (if deployed)
- Add endpoint to check JWT token validity: `POST /token/validate`
- Define post-authentication redirect logic:
  - After successful login, check if user has an `auto_redirect_url` set.
    - If set, service performs HTTP redirect to that URL.
    - If not set, return redirect URL or context for the client to handle.
  - Support custom redirect URLs for different user roles or client applications.
  - Document expected redirect behavior and auto redirect option in the OpenAPI spec and README.
- Restrict admin-only endpoints (e.g., auto redirect) to users with the admin role
- Log admin creation and access attempts securely (no sensitive data)
- Optionally require initial admin to change password on first login

## 5. Admin User Bootstrapping
- On first run or migration, check if an admin user exists
- If not, create a basic admin user:
  - Use environment variables for initial admin username, email, and password (`ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`)
  - Hash the password securely before storing
  - Set the admin role explicitly
- Never log or expose the plaintext password
- Document admin creation flow and environment variables in README

## 6. API Endpoints
- `POST /register`: Create new user
- `POST /login`: Authenticate user, return JWT
- `POST /token/validate`: Validate JWT token
- `GET /user`: Get current user data (auth required)
- `PUT /user`: Update user data (auth required)
- `PUT /user/password`: Change password (auth required)
- `PUT /user/recovery-email`: Change recovery email (auth required)
- `POST /user/recover`: Initiate password recovery
- `GET /users`: List users (admin only)
- `PUT /users/:id/roles`: Change user roles (admin only)
- `PUT /user/auto-redirect`: Set or update user's auto redirect URL (auth required)

## 7. OpenAPI Specification
- Document all endpoints using OpenAPI (Swagger)
- Specify redirect URL/context in login response schema
- Specify auto redirect logic and option in login response schema and documentation
- Generate and maintain an OpenAPI spec file (`openapi.yaml`)
- Use tools like `swaggo` or `go-swagger` for Go integration

## 8. Testing
- Write unit and integration tests for all modules and endpoints (backend and frontend)
- Test security edge cases (SQLi, XSS, brute force)
- Test brute-force protection and rate limiting
- Test admin creation and access restrictions
- Ensure RBAC logic is covered by tests
- Add automated tests for OpenAPI spec compliance
- Add frontend tests (component, integration, and API client)
- Set up test coverage reporting and CI integration

## Testing & Quality Practices
- Apply SOLID and DRY principles throughout backend and frontend code
- Use idiomatic Go and framework best practices
- Write modular, reusable, and well-documented code
- Ensure all tests (unit, integration, security, frontend) are maintainable and avoid duplication
- Use linters and static analysis tools (e.g., golangci-lint, eslint) in CI
- Review code for adherence to SOLID, DRY, and idiomatic standards before merging

## 9. Documentation
- Document API endpoints and RBAC model
- Add setup and deployment instructions
- Include OpenAPI spec for client integration
- Document redirect logic and integration points for downstream apps
- Document auto redirect feature, usage, and integration points
- Provide example integration flows for downstream services (e.g., how to validate JWT, how to handle redirects, how to request user info)
- Include sample client code snippets for common languages (Go, Python, JavaScript)
- Add troubleshooting and FAQ section for integration issues
- Maintain a changelog for API and integration updates
- Document how SOLID, DRY, and idiomatic Go practices are followed in the codebase
- Document admin bootstrapping, environment variables, and password change flow

## 10. Deployment
- Containerize with Docker
- Set up CI/CD pipeline
- Deploy to cloud or on-prem

## 11. After: Simple HTML Site for Login & User Data
- Create a small web frontend for login and user data display
- Use an easy-to-edit framework (e.g., Vue.js, React, or plain HTML + JS)
- Features:
  - Login form (calls backend API)
  - Display user data after login
  - Show error messages and loading states
  - Easy to customize and extend
- Document setup and integration steps for the frontend in the README
- Optionally containerize the frontend for deployment with the backend

---

**Next Steps:**
- Choose Go as the tech stack and start with project scaffolding.
- Set up OpenAPI documentation from the start.
- Follow steps above for incremental development.
