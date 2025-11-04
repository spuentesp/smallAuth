package models

import (
	"time"

	"gorm.io/gorm"
)

// RefreshToken represents a refresh token for extending user sessions
type RefreshToken struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	UserID    uint           `gorm:"not null;index" json:"user_id"`
	User      User           `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	Token     string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"token"`
	ExpiresAt time.Time      `gorm:"not null;index" json:"expires_at"`
	Revoked   bool           `gorm:"default:false;index" json:"revoked"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}
