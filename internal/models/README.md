# Database Models

This directory contains GORM models for users, roles, permissions, and join tables.

## Model Files
- `user.go`: User model
- `role.go`: Role model
- `permission.go`: Permission model
- `user_role.go`: UserRole join table
- `role_permission.go`: RolePermission join table

## Note
The original `models.go` file has been deleted. Models are now split into separate files for clarity and maintainability, following idiomatic Go and SOLID principles. Use this directory for all model definitions and shared model logic if needed.
