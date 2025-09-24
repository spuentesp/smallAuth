package db

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/models"
)

// ConnectDB initializes and returns a GORM DB connection
func ConnectDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

// MigrateDB runs GORM auto-migrations for all models
func MigrateDB(db *gorm.DB) error {
	return db.AutoMigrate(
		&config.Config{}, // not a DB model, skip
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.UserRole{},
		&models.RolePermission{},
		&models.PasswordRecoveryToken{},
	)
}
