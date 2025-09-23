package rbac

import (
	"github.com/gin-gonic/gin"
	"github.com/example/smallauth/internal/models"
)

// PermissionChecker defines the interface for checking user permissions
// This can be extended for custom logic or testing

type PermissionChecker interface {
	HasPermission(user *models.User, permission string) bool
}

// DefaultPermissionChecker implements PermissionChecker using GORM models
// This can be replaced with mocks or custom logic for testing

type DefaultPermissionChecker struct{}

func (d *DefaultPermissionChecker) HasPermission(user *models.User, permission string) bool {
	for _, role := range user.Roles {
		for _, perm := range role.Permissions {
			if perm.Name == permission {
				return true
			}
		}
	}
	return false
}

// RBACMiddleware returns a Gin middleware that checks for required permission
func RBACMiddleware(permission string, checker PermissionChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}
		userModel, ok := user.(*models.User)
		if !ok {
			c.AbortWithStatusJSON(500, gin.H{"error": "Invalid user type"})
			return
		}
		if !checker.HasPermission(userModel, permission) {
			c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.Next()
	}
}
