package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/example/smallauth/internal/models"
	"gorm.io/gorm"
)

// GenerateRefreshToken creates a new secure random refresh token
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CreateRefreshToken generates and stores a refresh token in the database
func CreateRefreshToken(db *gorm.DB, userID uint, expirationDays int) (*models.RefreshToken, error) {
	tokenStr, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	refreshToken := &models.RefreshToken{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(time.Duration(expirationDays) * 24 * time.Hour),
		Revoked:   false,
	}

	if err := db.Create(refreshToken).Error; err != nil {
		return nil, err
	}

	return refreshToken, nil
}

// ValidateRefreshToken checks if a refresh token is valid and not expired or revoked
func ValidateRefreshToken(db *gorm.DB, tokenStr string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	if err := db.Where("token = ?", tokenStr).First(&token).Error; err != nil {
		return nil, err
	}

	// Check if token is revoked
	if token.Revoked {
		return nil, gorm.ErrRecordNotFound
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, gorm.ErrRecordNotFound
	}

	return &token, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func RevokeRefreshToken(db *gorm.DB, tokenStr string) error {
	return db.Model(&models.RefreshToken{}).Where("token = ?", tokenStr).Update("revoked", true).Error
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a specific user
func RevokeAllUserRefreshTokens(db *gorm.DB, userID uint) error {
	return db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

// CleanupExpiredTokens removes expired refresh tokens from the database
func CleanupExpiredTokens(db *gorm.DB) error {
	return db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error
}
