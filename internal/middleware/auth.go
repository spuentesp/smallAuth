package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/models"
	"github.com/example/smallauth/internal/rbac"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// RateLimiterConfig holds config for rate limiting and brute-force protection
// Add to config.go and load from env
var (
	loginAttempts      = make(map[string]*attemptInfo)
	loginAttemptsMutex sync.Mutex
)

// Add a global logger
var Logger = logrus.New()

type attemptInfo struct {
	Count        int
	LastFailed   time.Time
	BlockedUntil time.Time
}

// RateLimitMiddleware limits requests per IP (simple in-memory)
func RateLimitMiddleware(maxRequests int, window time.Duration) gin.HandlerFunc {
	visits := make(map[string][]time.Time)
	var mu sync.Mutex
	return func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		now := time.Now()
		visits[ip] = append(visits[ip], now)
		// Remove old visits
		cutoff := now.Add(-window)
		newVisits := []time.Time{}
		for _, t := range visits[ip] {
			if t.After(cutoff) {
				newVisits = append(newVisits, t)
			}
		}
		visits[ip] = newVisits
		if len(newVisits) > maxRequests {
			mu.Unlock()
			c.AbortWithStatusJSON(429, gin.H{"error": "rate limit exceeded"})
			return
		}
		mu.Unlock()
		c.Next()
	}
}

// BruteForceProtectionMiddleware blocks repeated failed logins
func BruteForceProtectionMiddleware(maxAttempts int, blockDuration time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		loginAttemptsMutex.Lock()
		info, exists := loginAttempts[ip]
		if !exists {
			info = &attemptInfo{}
			loginAttempts[ip] = info
		}
		if time.Now().Before(info.BlockedUntil) {
			loginAttemptsMutex.Unlock()
			c.AbortWithStatusJSON(429, gin.H{"error": "too many failed login attempts, try again later"})
			return
		}
		loginAttemptsMutex.Unlock()
		c.Next()
	}
}

// Call this after a failed login attempt
func RegisterFailedLogin(ip string, maxAttempts int, blockDuration time.Duration) {
	loginAttemptsMutex.Lock()
	info, exists := loginAttempts[ip]
	if !exists {
		info = &attemptInfo{}
		loginAttempts[ip] = info
	}
	info.Count++
	info.LastFailed = time.Now()
	if info.Count >= maxAttempts {
		info.BlockedUntil = time.Now().Add(blockDuration)
		info.Count = 0 // reset after block
	}
	loginAttemptsMutex.Unlock()
}

// Call this after a successful login
func ResetLoginAttempts(ip string) {
	loginAttemptsMutex.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMutex.Unlock()
}

// Example usage in middleware
func logRequest(c *gin.Context, status int, msg string) {
	Logger.WithFields(logrus.Fields{
		"method": c.Request.Method,
		"path":   c.Request.URL.Path,
		"ip":     c.ClientIP(),
		"status": status,
	}).Info(msg)
}

// AuthMiddleware validates JWT and loads user into context
func AuthMiddleware(cfg *config.Config, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			logRequest(c, http.StatusUnauthorized, "missing token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil {
			logRequest(c, http.StatusUnauthorized, "invalid token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		userID, ok := claims["sub"].(float64)
		if !ok {
			logRequest(c, http.StatusUnauthorized, "invalid token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}
		var user models.User
		if err := db.Where("id = ?", uint(userID)).Preload("Roles.Permissions").First(&user).Error; err != nil {
			logRequest(c, http.StatusUnauthorized, "user not found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}
		logRequest(c, http.StatusOK, "user authenticated")
		c.Set("user", &user)
		c.Next()
	}
}

// SetupAdminRBAC applies RBAC middleware to admin routes
func SetupAdminRBAC(router *gin.RouterGroup) {
	checker := &rbac.DefaultPermissionChecker{}
	router.Use(rbac.RBACMiddleware("manage_users", checker))
}

// RBAC middleware usage example:
// Use rbac.RBACMiddleware(permission, checker) in your router setup.
// Example: router.Use(rbac.RBACMiddleware("manage_users", &rbac.DefaultPermissionChecker{}))
