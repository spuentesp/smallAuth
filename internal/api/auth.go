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
	Token       string `json:"token"`
	RedirectURL string `json:"redirect_url,omitempty"`
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
		resp := LoginResponse{Token: token}
		if user.AutoRedirectURL != "" {
			resp.RedirectURL = user.AutoRedirectURL
		}
		c.JSON(http.StatusOK, resp)
	}
}

func generateJWT(user *models.User, cfg *config.Config) (string, error) {
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"email":    user.Email,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
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
