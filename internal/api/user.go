package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/example/smallauth/internal/auth"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/mail"
	"github.com/example/smallauth/internal/middleware"
	"github.com/example/smallauth/internal/models"
)

// RegisterUserRequest is the payload for registration
// You can extend this for more fields

type RegisterUserRequest struct {
	Username      string `json:"username" binding:"required"`
	Email         string `json:"email" binding:"required,email"`
	RecoveryEmail string `json:"recovery_email" binding:"required,email"`
	Password      string `json:"password" binding:"required"`
}

func logAPI(c *gin.Context, status int, msg string, fields logrus.Fields) {
	allFields := logrus.Fields{
		"method": c.Request.Method,
		"path":   c.Request.URL.Path,
		"ip":     c.ClientIP(),
		"status": status,
	}
	for k, v := range fields {
		allFields[k] = v
	}
	middleware.Logger.WithFields(allFields).Info(msg)
}

func RegisterUserHandler(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logAPI(c, http.StatusBadRequest, "invalid registration request", logrus.Fields{"error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		strengthCfg := auth.PasswordStrengthConfig{
			MinLength:     cfg.PasswordMinLength,
			RequireUpper:  cfg.PasswordRequireUpper,
			RequireLower:  cfg.PasswordRequireLower,
			RequireDigit:  cfg.PasswordRequireDigit,
			RequireSymbol: cfg.PasswordRequireSymbol,
		}
		if !auth.ValidatePasswordStrength(req.Password, strengthCfg) {
			logAPI(c, http.StatusBadRequest, "weak password on registration", logrus.Fields{"username": req.Username})
			c.JSON(http.StatusBadRequest, gin.H{"error": "password does not meet strength requirements"})
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			logAPI(c, http.StatusInternalServerError, "failed to hash password", logrus.Fields{"username": req.Username, "error": err.Error()})
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
			logAPI(c, http.StatusInternalServerError, "failed to create user", logrus.Fields{"username": req.Username, "error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
			return
		}
		logAPI(c, http.StatusCreated, "user registered", logrus.Fields{"username": req.Username, "user_id": user.ID})
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
			logAPI(c, http.StatusBadRequest, "invalid password recovery request", logrus.Fields{"error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		var user models.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			logAPI(c, http.StatusOK, "password recovery requested for non-existent email", logrus.Fields{"email": req.Email})
			c.JSON(http.StatusOK, gin.H{"message": "If the email exists, recovery instructions have been sent."})
			return
		}
		err := auth.RecoverPassword(&user, mailer, cfg, db)
		if err != nil {
			logAPI(c, http.StatusInternalServerError, "failed to send recovery email", logrus.Fields{"user_id": user.ID, "error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send recovery email"})
			return
		}
		logAPI(c, http.StatusOK, "password recovery email sent", logrus.Fields{"user_id": user.ID})
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
			logAPI(c, http.StatusUnauthorized, "unauthorized password change", nil)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			logAPI(c, http.StatusInternalServerError, "invalid user type on password change", nil)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user type"})
			return
		}
		var req ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logAPI(c, http.StatusBadRequest, "invalid password change request", logrus.Fields{"user_id": userModel.ID, "error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		err := auth.ChangeUserPassword(userModel, req.OldPassword, req.NewPassword, cfg)
		if err != nil {
			logAPI(c, http.StatusBadRequest, "password change failed", logrus.Fields{"user_id": userModel.ID, "error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Save(userModel).Error; err != nil {
			logAPI(c, http.StatusInternalServerError, "failed to update password", logrus.Fields{"user_id": userModel.ID, "error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
			return
		}
		logAPI(c, http.StatusOK, "password changed", logrus.Fields{"user_id": userModel.ID})
		c.JSON(http.StatusOK, gin.H{"message": "password changed"})
	}
}

// Update user data (auth required)
type UpdateUserRequest struct {
	Email           string `json:"email"`
	RecoveryEmail   string `json:"recovery_email"`
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

// Health check endpoint
func HealthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().UTC()})
	}
}
