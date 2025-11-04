package auth

import (
	"time"

	"github.com/example/smallauth/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// BlacklistToken adds a token to the blacklist
func BlacklistToken(db *gorm.DB, tokenStr string, expiresAt time.Time) error {
	blacklistEntry := &models.TokenBlacklist{
		Token:     tokenStr,
		ExpiresAt: expiresAt,
	}
	return db.Create(blacklistEntry).Error
}

// IsTokenBlacklisted checks if a token is in the blacklist
func IsTokenBlacklisted(db *gorm.DB, tokenStr string) bool {
	var count int64
	db.Model(&models.TokenBlacklist{}).Where("token = ? AND expires_at > ?", tokenStr, time.Now()).Count(&count)
	return count > 0
}

// CleanupExpiredBlacklistTokens removes expired tokens from the blacklist
func CleanupExpiredBlacklistTokens(db *gorm.DB) error {
	return db.Where("expires_at < ?", time.Now()).Delete(&models.TokenBlacklist{}).Error
}

// ExtractExpirationFromToken extracts the expiration time from a JWT token
func ExtractExpirationFromToken(tokenStr string, secret string) (time.Time, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return time.Time{}, err
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, jwt.ErrTokenInvalidClaims
	}

	return time.Unix(int64(exp), 0), nil
}
