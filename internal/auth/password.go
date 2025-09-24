package auth

import (
	"errors"
	"unicode"

	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plaintext password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a plaintext password with a bcrypt hash
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// PasswordStrengthConfig defines requirements for password validation
type PasswordStrengthConfig struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool
}

// ValidatePasswordStrength checks if a password meets the configured requirements
func ValidatePasswordStrength(password string, cfg PasswordStrengthConfig) bool {
	if len(password) < cfg.MinLength {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSymbol = true
		}
	}
	if cfg.RequireUpper && !hasUpper {
		return false
	}
	if cfg.RequireLower && !hasLower {
		return false
	}
	if cfg.RequireDigit && !hasDigit {
		return false
	}
	if cfg.RequireSymbol && !hasSymbol {
		return false
	}
	return true
}

// ChangeUserPassword verifies the old password, validates the new password, and updates the hash
func ChangeUserPassword(user *models.User, oldPassword, newPassword string, cfg *config.Config) error {
	if !CheckPasswordHash(oldPassword, user.PasswordHash) {
		return ErrInvalidOldPassword
	}
	strengthCfg := PasswordStrengthConfig{
		MinLength:     cfg.PasswordMinLength,
		RequireUpper:  cfg.PasswordRequireUpper,
		RequireLower:  cfg.PasswordRequireLower,
		RequireDigit:  cfg.PasswordRequireDigit,
		RequireSymbol: cfg.PasswordRequireSymbol,
	}
	if !ValidatePasswordStrength(newPassword, strengthCfg) {
		return ErrWeakPassword
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	return nil // Persist user update in DB outside this function
}

var (
	ErrInvalidOldPassword = errors.New("invalid old password")
	ErrWeakPassword       = errors.New("new password does not meet strength requirements")
)
