package config

import (
	"os"
	"strconv"
)

// Config holds all configuration variables
type Config struct {
	DBHost                   string
	DBPort                   string
	DBUser                   string
	DBPassword               string
	DBName                   string
	JWTSecret                string
	AdminUsername            string
	AdminEmail               string
	AdminPassword            string
	SMTPHost                 string
	SMTPPort                 string
	SMTPUser                 string
	SMTPPassword             string
	PasswordMinLength        int
	PasswordRequireUpper     bool
	PasswordRequireLower     bool
	PasswordRequireDigit     bool
	PasswordRequireSymbol    bool
	PasswordRecoveryTokenTTL int // in seconds
	RateLimitMaxRequests     int
	RateLimitWindowSeconds   int
	BruteForceMaxAttempts    int
	BruteForceBlockSeconds   int
	FrontendBaseURL          string
	JWTExpirationHours       int    // JWT access token expiration in hours
	RefreshTokenExpirationDays int  // Refresh token expiration in days
	CORSAllowedOrigins       string // Comma-separated list of allowed origins
	CORSAllowCredentials     bool   // Allow credentials in CORS
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		DBHost:                   os.Getenv("DB_HOST"),
		DBPort:                   os.Getenv("DB_PORT"),
		DBUser:                   os.Getenv("DB_USER"),
		DBPassword:               os.Getenv("DB_PASSWORD"),
		DBName:                   os.Getenv("DB_NAME"),
		JWTSecret:                os.Getenv("JWT_SECRET"),
		AdminUsername:            os.Getenv("ADMIN_USERNAME"),
		AdminEmail:               os.Getenv("ADMIN_EMAIL"),
		AdminPassword:            os.Getenv("ADMIN_PASSWORD"),
		SMTPHost:                 os.Getenv("SMTP_HOST"),
		SMTPPort:                 os.Getenv("SMTP_PORT"),
		SMTPUser:                 os.Getenv("SMTP_USER"),
		SMTPPassword:             os.Getenv("SMTP_PASSWORD"),
		PasswordMinLength:        getEnvInt("PASSWORD_MIN_LENGTH", 8),
		PasswordRequireUpper:     getEnvBool("PASSWORD_REQUIRE_UPPER", true),
		PasswordRequireLower:     getEnvBool("PASSWORD_REQUIRE_LOWER", true),
		PasswordRequireDigit:     getEnvBool("PASSWORD_REQUIRE_DIGIT", true),
		PasswordRequireSymbol:    getEnvBool("PASSWORD_REQUIRE_SYMBOL", true),
		PasswordRecoveryTokenTTL: getEnvInt("PASSWORD_RECOVERY_TOKEN_TTL", 86400), // default 24h
		RateLimitMaxRequests:     getEnvInt("RATE_LIMIT_MAX_REQUESTS", 100),
		RateLimitWindowSeconds:   getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 60),
		BruteForceMaxAttempts:    getEnvInt("BRUTE_FORCE_MAX_ATTEMPTS", 5),
		BruteForceBlockSeconds:   getEnvInt("BRUTE_FORCE_BLOCK_SECONDS", 300),
		FrontendBaseURL:          os.Getenv("FRONTEND_BASE_URL"),
		JWTExpirationHours:       getEnvInt("JWT_EXPIRATION_HOURS", 24),        // default 24 hours
		RefreshTokenExpirationDays: getEnvInt("REFRESH_TOKEN_EXPIRATION_DAYS", 30), // default 30 days
		CORSAllowedOrigins:       getEnvString("CORS_ALLOWED_ORIGINS", "*"),    // default allow all
		CORSAllowCredentials:     getEnvBool("CORS_ALLOW_CREDENTIALS", true),
	}
}

// Helper functions for env parsing
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if val == "true" || val == "1" {
			return true
		}
		if val == "false" || val == "0" {
			return false
		}
	}
	return defaultVal
}

func getEnvString(key string, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
