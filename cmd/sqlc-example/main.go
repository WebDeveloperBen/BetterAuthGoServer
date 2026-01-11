// Package main demonstrates using the sqlc-based store.
// This example shows how to connect to a database and use the store.
package main

import (
	"database/sql"
	"log"
	"log/slog"
	"os"
	"strings"

	_ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

func main() {
	dbURL := getEnv("DATABASE_URL", "sqlite://auth.db")

	// Create logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Connect to database using standard database/sql
	sqlDB, dialect, err := connectDB(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	// Create sqlc-based store
	store, err := db.New(sqlDB, dialect)
	if err != nil {
		log.Fatal("Failed to create store:", err)
	}

	// NOTE: Migrations are managed separately using golang-migrate or your preferred tool.
	// See db/migrations/ for migration files.
	// Example: migrate -path db/migrations/postgres -database $DATABASE_URL up

	logger.Info("Database connected",
		"dialect", dialect,
	)

	// The store is ready to use with auth.New()
	_ = store

	logger.Info("sqlc store is ready for use")
}

// connectDB creates a standard sql.DB connection based on the DATABASE_URL scheme
func connectDB(dbURL string) (*sql.DB, db.Dialect, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		sqldb, err := sql.Open("postgres", dbURL)
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectPostgres, nil

	case strings.HasPrefix(dbURL, "sqlite://"):
		path := strings.TrimPrefix(dbURL, "sqlite://")
		sqldb, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectSQLite, nil

	default:
		// Assume SQLite file path
		sqldb, err := sql.Open("sqlite3", dbURL+"?_foreign_keys=on")
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectSQLite, nil
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
