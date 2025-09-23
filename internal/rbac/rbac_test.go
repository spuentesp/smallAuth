package rbac

import (
	"testing"
	"github.com/example/smallauth/internal/models"
)

func TestDefaultPermissionChecker_HasPermission(t *testing.T) {
	user := &models.User{
		Roles: []models.Role{
			{
				Name: "admin",
				Permissions: []models.Permission{
					{Name: "manage_users"},
					{Name: "view_reports"},
				},
			},
			{
				Name: "user",
				Permissions: []models.Permission{
					{Name: "view_profile"},
				},
			},
		},
	}
	checker := &DefaultPermissionChecker{}

	tests := []struct {
		perm     string
		expected bool
	}{
		{"manage_users", true},
		{"view_reports", true},
		{"view_profile", true},
		{"edit_profile", false},
		{"delete_user", false},
	}

	for _, tt := range tests {
		result := checker.HasPermission(user, tt.perm)
		if result != tt.expected {
			t.Errorf("HasPermission(%q) = %v, want %v", tt.perm, result, tt.expected)
		}
	}
}

func TestDefaultPermissionChecker_EmptyRoles(t *testing.T) {
	user := &models.User{Roles: []models.Role{}}
	checker := &DefaultPermissionChecker{}
	if checker.HasPermission(user, "any_permission") {
		t.Errorf("Expected false for user with no roles, got true")
	}
}

func TestDefaultPermissionChecker_EmptyPermissions(t *testing.T) {
	user := &models.User{
		Roles: []models.Role{
			{Name: "user", Permissions: []models.Permission{}},
		},
	}
	checker := &DefaultPermissionChecker{}
	if checker.HasPermission(user, "any_permission") {
		t.Errorf("Expected false for role with no permissions, got true")
	}
}

func TestDefaultPermissionChecker_DuplicatePermissions(t *testing.T) {
	user := &models.User{
		Roles: []models.Role{
			{Name: "admin", Permissions: []models.Permission{{Name: "manage_users"}, {Name: "manage_users"}}},
		},
	}
	checker := &DefaultPermissionChecker{}
	if !checker.HasPermission(user, "manage_users") {
		t.Errorf("Expected true for duplicate permission, got false")
	}
}

func TestDefaultPermissionChecker_CaseSensitivity(t *testing.T) {
	user := &models.User{
		Roles: []models.Role{
			{Name: "admin", Permissions: []models.Permission{{Name: "Manage_Users"}}},
		},
	}
	checker := &DefaultPermissionChecker{}
	if checker.HasPermission(user, "manage_users") {
		t.Errorf("Expected false for case-sensitive permission, got true")
	}
}
