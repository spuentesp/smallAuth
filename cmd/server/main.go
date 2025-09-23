package main

import (
	"fmt"
	"github.com/example/smallauth/internal/config"
	"github.com/example/smallauth/internal/db"
)

func main() {
	cfg := config.LoadConfig()
	_, err := db.ConnectDB(cfg)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	fmt.Println("Database connected. smallAuth server starting...")
	// TODO: Initialize Gin router, etc.
}
