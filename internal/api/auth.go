package api

import (
	"net/http"
	"time"

	"github.com/example/smallauth/internal/auth"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	RedirectURL  string `json:"redirect_url,omitempty"`
}

func LoginHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		var user models.User
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		token, err := generateJWT(&user, cfg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		// Generate refresh token
		refreshToken, err := auth.CreateRefreshToken(db, user.ID, cfg.RefreshTokenExpirationDays)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
			return
		}

		resp := LoginResponse{
			Token:        token,
			RefreshToken: refreshToken.Token,
		}
		if user.AutoRedirectURL != "" {
			resp.RedirectURL = user.AutoRedirectURL
		}
		c.JSON(http.StatusOK, resp)
	}
}

func generateJWT(user *models.User, cfg *config.Config) (string, error) {
	expirationTime := time.Duration(cfg.JWTExpirationHours) * time.Hour
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"email":    user.Email,
		"exp":      time.Now().Add(expirationTime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

// Token validation endpoint

type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

type ValidateTokenResponse struct {
	Valid  bool                   `json:"valid"`
	Claims map[string]interface{} `json:"claims,omitempty"`
}

func ValidateTokenHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ValidateTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(req.Token, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil {
			c.JSON(http.StatusOK, ValidateTokenResponse{Valid: false})
			return
		}
		c.JSON(http.StatusOK, ValidateTokenResponse{Valid: true, Claims: claims})
	}
}

// Refresh token endpoint

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func RefreshTokenHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Validate the refresh token
		refreshToken, err := auth.ValidateRefreshToken(db, req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
			return
		}

		// Load the user
		var user models.User
		if err := db.Where("id = ?", refreshToken.UserID).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		// Generate new access token
		newAccessToken, err := generateJWT(&user, cfg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		// Generate new refresh token and revoke the old one
		auth.RevokeRefreshToken(db, req.RefreshToken)
		newRefreshToken, err := auth.CreateRefreshToken(db, user.ID, cfg.RefreshTokenExpirationDays)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
			return
		}

		c.JSON(http.StatusOK, RefreshTokenResponse{
			Token:        newAccessToken,
			RefreshToken: newRefreshToken.Token,
		})
	}
}

// Logout endpoint

func LogoutHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
			return
		}

		// Extract token without Bearer prefix
		const bearerPrefix = "Bearer "
		if len(authHeader) < len(bearerPrefix) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token format"})
			return
		}
		tokenStr := authHeader[len(bearerPrefix):]

		// Extract expiration time from token
		expiresAt, err := auth.ExtractExpirationFromToken(tokenStr, cfg.JWTSecret)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
			return
		}

		// Add token to blacklist
		if err := auth.BlacklistToken(db, tokenStr, expiresAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
			return
		}

		// Get user from context to revoke refresh tokens
		userInterface, exists := c.Get("user")
		if exists {
			if user, ok := userInterface.(*models.User); ok {
				// Revoke all refresh tokens for this user
				auth.RevokeAllUserRefreshTokens(db, user.ID)
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
	}
}
