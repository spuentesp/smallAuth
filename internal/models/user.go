package models

import (
	"time"
	"gorm.io/gorm"
)

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
