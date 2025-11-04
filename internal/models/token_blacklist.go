package models

import (
	"time"

	"gorm.io/gorm"
)

// TokenBlacklist represents a blacklisted JWT token
type TokenBlacklist struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Token     string         `gorm:"type:varchar(500);uniqueIndex;not null" json:"token"` // Store JWT hash or full token
	ExpiresAt time.Time      `gorm:"not null;index" json:"expires_at"`                    // When the original token expires
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}
