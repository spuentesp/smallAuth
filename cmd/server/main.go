package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/example/smallauth/internal/api"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/db"
	"github.com/example/smallauth/internal/mail"
	"github.com/example/smallauth/internal/middleware"
	"github.com/gin-gonic/gin"
)

// @title SmallAuth API
// @version 1.0
// @description Auth microservice with RBAC, password recovery, and security features
// @host localhost:8080
// @BasePath /

func main() {
	cfg := config.LoadConfig()
	conn, err := db.ConnectDB(cfg)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	fmt.Println("Database connected. smallAuth server starting...")

	// Run DB migrations
	if err := db.MigrateDB(conn); err != nil {
		panic("failed to run migrations: " + err.Error())
	}
	fmt.Println("Database migrations complete.")

	// Check DB connection
	dbSQL, err := conn.DB()
	if err != nil {
		panic("failed to get DB instance: " + err.Error())
	}
	if err := dbSQL.Ping(); err != nil {
		panic("failed to ping database: " + err.Error())
	}
	fmt.Println("Database ping successful.")

	// Setup Gin router
	router := gin.Default()
	mailer := mail.NewSMTPMailer(cfg)

	// Public endpoints with rate limiting
	router.Use(middleware.RateLimitMiddleware(cfg.RateLimitMaxRequests, time.Duration(cfg.RateLimitWindowSeconds)*time.Second))

	// Public endpoints
	router.POST("/register", api.RegisterUserHandler(conn, cfg))
	router.POST("/login", middleware.BruteForceProtectionMiddleware(cfg.BruteForceMaxAttempts, time.Duration(cfg.BruteForceBlockSeconds)*time.Second), func(c *gin.Context) {
		// Call the actual login handler
		api.LoginHandler(conn, cfg)(c)
		// If login failed, register failed attempt
		if c.Writer.Status() == http.StatusUnauthorized {
			middleware.RegisterFailedLogin(c.ClientIP(), cfg.BruteForceMaxAttempts, time.Duration(cfg.BruteForceBlockSeconds)*time.Second)
		} else if c.Writer.Status() == http.StatusOK {
			middleware.ResetLoginAttempts(c.ClientIP())
		}
	})
	router.POST("/token/validate", api.ValidateTokenHandler(cfg))
	router.POST("/user/recover", api.RecoverPasswordHandler(conn, cfg, mailer))

	// Authenticated endpoints
	authMW := middleware.AuthMiddleware(cfg, conn)
	authGroup := router.Group("/")
	authGroup.Use(authMW)
	authGroup.GET("/user", api.GetCurrentUserHandler(conn))
	authGroup.PUT("/user", api.UpdateUserHandler(conn))
	authGroup.PUT("/user/password", api.ChangePasswordHandler(conn, cfg))
	authGroup.PUT("/user/auto-redirect", api.SetAutoRedirectHandler(conn))

	// Admin endpoints (add RBAC middleware for permission checks)
	adminGroup := authGroup.Group("/admin")
	middleware.SetupAdminRBAC(adminGroup)
	adminGroup.GET("/users", api.ListUsersHandler(conn))
	adminGroup.PUT("/users/:id/roles", api.ChangeUserRolesHandler(conn))

	// Start server
	router.Run()
}
