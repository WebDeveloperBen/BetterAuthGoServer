package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"

	_ "github.com/mattn/go-sqlite3"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "sqlite://auth.db"
	}

	bunDB, err := connectDB(dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer bunDB.Close()

	s := store.New(bunDB)
	ctx := context.Background()

	cmd := os.Args[1]
	switch cmd {
	case "up", "migrate":
		if err := s.Migrate(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Migrations applied successfully")

	case "status":
		// List tables that would be created
		migrations := s.Migrations()
		fmt.Println("Models to migrate:")
		fmt.Println("------------------")
		for _, m := range migrations {
			fmt.Printf("  %T\n", m)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: migrate <command>

Commands:
  up, migrate     Create tables if they don't exist
  status          Show models that will be migrated

Environment:
  DATABASE_URL    Database connection string (default: sqlite://auth.db)
                  Examples:
                    sqlite://auth.db
                    postgres://user:pass@localhost:5432/dbname?sslmode=disable

Note: This tool creates tables using Bun's model-based migrations.
      Tables are created with IfNotExists() so it's safe to run multiple times.
      Plugin tables are created automatically when plugins are initialized.`)
}

func connectDB(dbURL string) (*bun.DB, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dbURL)))
		return bun.NewDB(sqldb, pgdialect.New()), nil

	case strings.HasPrefix(dbURL, "sqlite://"):
		path := strings.TrimPrefix(dbURL, "sqlite://")
		sqldb, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
		if err != nil {
			return nil, err
		}
		return bun.NewDB(sqldb, sqlitedialect.New()), nil

	default:
		sqldb, err := sql.Open("sqlite3", dbURL+"?_foreign_keys=on")
		if err != nil {
			return nil, err
		}
		return bun.NewDB(sqldb, sqlitedialect.New()), nil
	}
}
