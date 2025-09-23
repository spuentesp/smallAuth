package main

import (
	"fmt"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/db"
	"os"
)

func main() {
	cfg := config.LoadConfig()
	conn, err := db.ConnectDB(cfg)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	fmt.Println("Database connected. smallAuth server starting...")

	// Check DB connection
	dbSQL, err := conn.DB()
	if err != nil {
		panic("failed to get DB instance: " + err.Error())
	}
	if err := dbSQL.Ping(); err != nil {
		panic("failed to ping database: " + err.Error())
	}
	fmt.Println("Database ping successful.")

	// Optional: Exit after DB check for now
	os.Exit(0)
}
