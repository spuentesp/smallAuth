package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/mail"
	"github.com/example/smallauth/internal/models"
	"gorm.io/gorm"
)

// GenerateRecoveryToken generates a secure, random, time-limited token
func GenerateRecoveryToken(user *models.User) string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "" // In production, handle error properly
	}
	return base64.URLEncoding.EncodeToString(b)
}

// SaveRecoveryToken stores the token and expiry in DB
func SaveRecoveryToken(db *gorm.DB, userID uint, token string, expiry time.Time) error {
	rec := &models.PasswordRecoveryToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiry,
	}
	return db.Create(rec).Error
}

// ValidateRecoveryToken checks token validity and expiry
func ValidateRecoveryToken(db *gorm.DB, token string) (*models.PasswordRecoveryToken, error) {
	rec := &models.PasswordRecoveryToken{}
	err := db.Where("token = ?", token).First(rec).Error
	if err != nil {
		return nil, err
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, errors.New("token expired")
	}
	return rec, nil
}

// InvalidateRecoveryToken deletes the token after use
func InvalidateRecoveryToken(db *gorm.DB, token string) error {
	return db.Where("token = ?", token).Delete(&models.PasswordRecoveryToken{}).Error
}

// SendRecoveryEmail sends a password recovery email using the mail module
func SendRecoveryEmail(user *models.User, token string, mailer mail.Mailer, cfg *config.Config) error {
	subject := "Password Recovery Instructions"
	resetURL := fmt.Sprintf("%s/reset?token=%s", cfg.FrontendBaseURL, token)
	htmlBody := fmt.Sprintf(`<h2>Password Reset</h2><p>Click <a href="%s">here</a> to reset your password. This link will expire soon.</p>`, resetURL)
	return mailer.SendHTML(user.RecoveryEmail, subject, htmlBody)
}

// RecoverPassword is the main entry for password recovery
func RecoverPassword(user *models.User, mailer mail.Mailer, cfg *config.Config, db *gorm.DB) error {
	token := GenerateRecoveryToken(user)
	expiry := time.Now().Add(time.Duration(cfg.PasswordRecoveryTokenTTL) * time.Second)
	err := SaveRecoveryToken(db, user.ID, token, expiry)
	if err != nil {
		return err
	}
	return SendRecoveryEmail(user, token, mailer, cfg)
}
