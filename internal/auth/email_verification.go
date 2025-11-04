package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/mail"
	"github.com/example/smallauth/internal/models"
	"gorm.io/gorm"
)

// GenerateEmailVerificationToken creates a new secure random token for email verification
func GenerateEmailVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CreateEmailVerificationToken generates and stores an email verification token
func CreateEmailVerificationToken(db *gorm.DB, userID uint, ttlSeconds int) (*models.EmailVerificationToken, error) {
	tokenStr, err := GenerateEmailVerificationToken()
	if err != nil {
		return nil, err
	}

	// Delete any existing verification tokens for this user
	db.Where("user_id = ?", userID).Delete(&models.EmailVerificationToken{})

	verificationToken := &models.EmailVerificationToken{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}

	if err := db.Create(verificationToken).Error; err != nil {
		return nil, err
	}

	return verificationToken, nil
}

// ValidateEmailVerificationToken checks if a verification token is valid and not expired
func ValidateEmailVerificationToken(db *gorm.DB, tokenStr string) (*models.EmailVerificationToken, error) {
	var token models.EmailVerificationToken
	if err := db.Where("token = ?", tokenStr).First(&token).Error; err != nil {
		return nil, err
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, gorm.ErrRecordNotFound
	}

	return &token, nil
}

// VerifyUserEmail marks a user's email as verified and deletes the verification token
func VerifyUserEmail(db *gorm.DB, tokenStr string) error {
	token, err := ValidateEmailVerificationToken(db, tokenStr)
	if err != nil {
		return err
	}

	// Update user's email_verified field
	if err := db.Model(&models.User{}).Where("id = ?", token.UserID).Update("email_verified", true).Error; err != nil {
		return err
	}

	// Delete the verification token
	return db.Delete(&token).Error
}

// SendVerificationEmail sends an email verification link to the user
func SendVerificationEmail(db *gorm.DB, cfg *config.Config, mailer mail.Mailer, user *models.User) error {
	// Create verification token with 24 hour expiration
	token, err := CreateEmailVerificationToken(db, user.ID, 86400)
	if err != nil {
		return err
	}

	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", cfg.FrontendBaseURL, token.Token)

	subject := "Verify Your Email Address"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Email Verification</h2>
			<p>Hello %s,</p>
			<p>Thank you for registering! Please verify your email address by clicking the link below:</p>
			<p><a href="%s">Verify Email Address</a></p>
			<p>Or copy and paste this URL into your browser:</p>
			<p>%s</p>
			<p>This link will expire in 24 hours.</p>
			<p>If you did not create an account, please ignore this email.</p>
		</body>
		</html>
	`, user.Username, verificationURL, verificationURL)

	return mailer.SendHTML(user.Email, subject, body)
}

// ResendVerificationEmail creates a new verification token and sends it to the user
func ResendVerificationEmail(db *gorm.DB, cfg *config.Config, mailer mail.Mailer, userID uint) error {
	var user models.User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}

	// Check if already verified
	if user.EmailVerified {
		return fmt.Errorf("email already verified")
	}

	return SendVerificationEmail(db, cfg, mailer, &user)
}
