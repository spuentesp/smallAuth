package api

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/example/smallauth/internal/models"
	"github.com/example/smallauth/internal/auth"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/mail"
)

// RegisterUserRequest is the payload for registration
// You can extend this for more fields

type RegisterUserRequest struct {
	Username      string `json:"username" binding:"required"`
	Email         string `json:"email" binding:"required,email"`
	RecoveryEmail string `json:"recovery_email" binding:"required,email"`
	Password      string `json:"password" binding:"required"`
}

func RegisterUserHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		strengthCfg := auth.PasswordStrengthConfig{
			MinLength:    cfg.PasswordMinLength,
			RequireUpper: cfg.PasswordRequireUpper,
			RequireLower: cfg.PasswordRequireLower,
			RequireDigit: cfg.PasswordRequireDigit,
			RequireSymbol: cfg.PasswordRequireSymbol,
		}
		if !auth.ValidatePasswordStrength(req.Password, strengthCfg) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password does not meet strength requirements"})
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		user := &models.User{
			Username:      req.Username,
			Email:         req.Email,
			RecoveryEmail: req.RecoveryEmail,
			PasswordHash:  hash,
		}
		if err := db.Create(user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "user registered"})
	}
}

// Password recovery endpoint

type RecoverPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func RecoverPasswordHandler(db *gorm.DB, cfg *config.Config, mailer mail.Mailer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RecoverPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		var user models.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			// Always respond generically
			c.JSON(http.StatusOK, gin.H{"message": "If the email exists, recovery instructions have been sent."})
			return
		}
		err := auth.RecoverPassword(&user, mailer, cfg, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send recovery email"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, recovery instructions have been sent."})
	}
}

// Get current user data (auth required)
func GetCurrentUserHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user type"})
			return
		}
		c.JSON(http.StatusOK, userModel)
	}
}

// Change password (auth required)
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func ChangePasswordHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user type"})
			return
		}
		var req ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		err := auth.ChangeUserPassword(userModel, req.OldPassword, req.NewPassword, cfg)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Save(userModel).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "password changed"})
	}
}

// Update user data (auth required)
type UpdateUserRequest struct {
	Email         string `json:"email"`
	RecoveryEmail string `json:"recovery_email"`
	AutoRedirectURL string `json:"auto_redirect_url"`
}

func UpdateUserHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user type"})
			return
		}
		var req UpdateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if req.Email != "" {
			userModel.Email = req.Email
		}
		if req.RecoveryEmail != "" {
			userModel.RecoveryEmail = req.RecoveryEmail
		}
		if req.AutoRedirectURL != "" {
			userModel.AutoRedirectURL = req.AutoRedirectURL
		}
		if err := db.Save(userModel).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "user updated"})
	}
}

// Set or update user's auto redirect URL (auth required)
type SetAutoRedirectRequest struct {
	AutoRedirectURL string `json:"auto_redirect_url" binding:"required"`
}

func SetAutoRedirectHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user type"})
			return
		}
		var req SetAutoRedirectRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		userModel.AutoRedirectURL = req.AutoRedirectURL
		if err := db.Save(userModel).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auto redirect URL"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "auto redirect URL updated"})
	}
}

// List users (admin only)
func ListUsersHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users []models.User
		if err := db.Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
			return
		}
		c.JSON(http.StatusOK, users)
	}
}

// Change user roles (admin only)
type ChangeUserRolesRequest struct {
	RoleIDs []uint `json:"role_ids" binding:"required"`
}

func ChangeUserRolesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ChangeUserRolesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		userID := c.Param("id")
		var user models.User
		if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		var roles []models.Role
		if err := db.Where("id IN ?", req.RoleIDs).Find(&roles).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to find roles"})
			return
		}
		user.Roles = roles
		if err := db.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user roles"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "user roles updated"})
	}
}
