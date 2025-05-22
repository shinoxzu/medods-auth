package main

import (
	"database/sql"
	"log/slog"
	"os"

	"github.com/pressly/goose/v3"
)

func runMigrations(db *sql.DB) {
	if err := goose.SetDialect("postgres"); err != nil {
		slog.Error("Failed to set database dialect", "error", err)
		os.Exit(1)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}
}
