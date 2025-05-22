package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func InitDB(dbConnString string) (*sqlx.DB, error) {
	slog.Info("Initializing database connection")

	db, err := sqlx.Connect("postgres", dbConnString)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		slog.Error("Failed to ping database", "error", err)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("Database connection established")
	return db, nil
}
