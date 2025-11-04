package api

import (
	"net/http"

	"github.com/example/smallauth/internal/auth"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/mail"
	"github.com/example/smallauth/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// VerifyEmailHandler verifies a user's email address using a token
func VerifyEmailHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req VerifyEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		if err := auth.VerifyUserEmail(db, req.Token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired verification token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
	}
}

// ResendVerificationEmailHandler sends a new verification email to the current user
func ResendVerificationEmailHandler(db *gorm.DB, cfg *config.Config, mailer mail.Mailer) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by AuthMiddleware)
		userInterface, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		user, ok := userInterface.(*models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user context"})
			return
		}

		if err := auth.ResendVerificationEmail(db, cfg, mailer, user.ID); err != nil {
			logrus.WithError(err).Error("Failed to resend verification email")
			if err.Error() == "email already verified" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "email already verified"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send verification email"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "verification email sent"})
	}
}
