// Package main demonstrates using the sqlc-based store.
// This is an example of how the auth package can be used with
// standard database/sql instead of Bun ORM.
package main

import (
	"context"
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
	defer sqlDB.Close()

	// Create sqlc-based store
	store, err := db.New(sqlDB, dialect)
	if err != nil {
		log.Fatal("Failed to create store:", err)
	}

	// Run migrations
	if err := store.Migrate(context.Background()); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	logger.Info("Database connected and migrated",
		"dialect", dialect,
	)

	// Example: Create a user
	// user := &models.User{
	// 	ID:        uuid.New().String(),
	// 	Email:     "test@example.com",
	// 	Name:      "Test User",
	// 	Role:      "user",
	// 	CreatedAt: time.Now(),
	// 	UpdatedAt: time.Now(),
	// }
	// if err := store.CreateUser(context.Background(), user); err != nil {
	// 	log.Fatal("Failed to create user:", err)
	// }

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
