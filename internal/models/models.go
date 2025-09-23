package models

import (
	"time"
	"gorm.io/gorm"
)

// Models have been split into separate files: user.go, role.go, permission.go, user_role.go, role_permission.go
// This file can be removed or used for shared model logic if needed.

// User model
type User struct {
	ID              uint           `gorm:"primaryKey"`
	Username        string         `gorm:"uniqueIndex;not null"`
	PasswordHash    string         `gorm:"not null"`
	Email           string         `gorm:"uniqueIndex;not null"`
	RecoveryEmail   string         `gorm:"not null"`
	AutoRedirectURL string         `gorm:"type:text"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
	Roles           []Role         `gorm:"many2many:user_roles;"`
}

// Role model
type Role struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	Permissions []Permission `gorm:"many2many:role_permissions;"`
	Users       []User       `gorm:"many2many:user_roles;"`
}

// Permission model
type Permission struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	Roles       []Role `gorm:"many2many:role_permissions;"`
}

// UserRole join table
type UserRole struct {
	UserID uint `gorm:"primaryKey"`
	RoleID uint `gorm:"primaryKey"`
}

// RolePermission join table
type RolePermission struct {
	RoleID       uint `gorm:"primaryKey"`
	PermissionID uint `gorm:"primaryKey"`
}
