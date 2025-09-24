package auth

import (
	"testing"

	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/models"
)

func TestHashPasswordAndCheckPasswordHash(t *testing.T) {
	password := "supersecret123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == password {
		t.Error("Hash should not match the original password")
	}
	if !CheckPasswordHash(password, hash) {
		t.Error("CheckPasswordHash should return true for correct password")
	}
	if CheckPasswordHash("wrongpassword", hash) {
		t.Error("CheckPasswordHash should return false for incorrect password")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	cfg := PasswordStrengthConfig{
		MinLength:     8,
		RequireUpper:  true,
		RequireLower:  true,
		RequireDigit:  true,
		RequireSymbol: true,
	}

	tests := []struct {
		password string
		expected bool
		desc     string
	}{
		{"Short1!", false, "too short"},
		{"nouppercase1!", false, "missing uppercase"},
		{"NOLOWERCASE1!", false, "missing lowercase"},
		{"NoDigit!", false, "missing digit"},
		{"NoSymbol1", false, "missing symbol"},
		{"Valid1!Password", true, "valid password"},
		{"ValidPassword1!", true, "valid password"},
	}

	for _, tt := range tests {
		result := ValidatePasswordStrength(tt.password, cfg)
		if result != tt.expected {
			t.Errorf("%s: ValidatePasswordStrength(%q) = %v, want %v", tt.desc, tt.password, result, tt.expected)
		}
	}
}

func TestChangeUserPassword(t *testing.T) {
	cfg := &PasswordStrengthConfig{
		MinLength:     8,
		RequireUpper:  true,
		RequireLower:  true,
		RequireDigit:  true,
		RequireSymbol: true,
	}
	appCfg := &config.Config{
		PasswordMinLength:     cfg.MinLength,
		PasswordRequireUpper:  cfg.RequireUpper,
		PasswordRequireLower:  cfg.RequireLower,
		PasswordRequireDigit:  cfg.RequireDigit,
		PasswordRequireSymbol: cfg.RequireSymbol,
	}
	oldPassword := "Valid1!Password"
	userHash, _ := HashPassword(oldPassword)
	user := &models.User{PasswordHash: userHash}

	// Success case
	newPassword := "NewValid1!Password"
	err := ChangeUserPassword(user, oldPassword, newPassword, appCfg)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if !CheckPasswordHash(newPassword, user.PasswordHash) {
		t.Error("Password hash not updated correctly")
	}

	// Wrong old password
	err = ChangeUserPassword(user, "wrongOldPassword", newPassword, appCfg)
	if err != ErrInvalidOldPassword {
		t.Errorf("Expected ErrInvalidOldPassword, got %v", err)
	}

	// Weak new password
	weakPassword := "short"
	err = ChangeUserPassword(user, newPassword, weakPassword, appCfg)
	if err != ErrWeakPassword {
		t.Errorf("Expected ErrWeakPassword, got %v", err)
	}
}
