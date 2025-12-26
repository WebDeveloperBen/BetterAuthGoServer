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
	"github.com/uptrace/bun/migrate"

	_ "github.com/mattn/go-sqlite3"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/store/migrations"
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

	migrator := migrate.NewMigrator(bunDB, migrations.Migrations)
	ctx := context.Background()

	// Initialize migration tables
	if err := migrator.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init migrator: %v\n", err)
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "up", "migrate":
		group, err := migrator.Migrate(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
			os.Exit(1)
		}
		if group.IsZero() {
			fmt.Println("No new migrations to run")
		} else {
			fmt.Printf("Migrated: %s\n", group)
		}

	case "down", "rollback":
		group, err := migrator.Rollback(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n", err)
			os.Exit(1)
		}
		if group.IsZero() {
			fmt.Println("No migrations to rollback")
		} else {
			fmt.Printf("Rolled back: %s\n", group)
		}

	case "status":
		ms, err := migrator.MigrationsWithStatus(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get status: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Migration Status:")
		fmt.Println("-----------------")
		for _, m := range ms {
			status := "pending"
			if !m.IsApplied() {
				status = "pending"
			} else {
				status = "applied"
			}
			fmt.Printf("  %s: %s\n", m.Name, status)
		}

	case "create":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: migrate create <name>")
			os.Exit(1)
		}
		name := os.Args[2]
		files, err := migrator.CreateSQLMigrations(ctx, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create migration: %v\n", err)
			os.Exit(1)
		}
		for _, f := range files {
			fmt.Printf("Created: %s\n", f.Path)
		}

	case "lock":
		if err := migrator.Lock(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to acquire lock: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Lock acquired")

	case "unlock":
		if err := migrator.Unlock(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to release lock: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Lock released")

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: migrate <command> [args]

Commands:
  up, migrate     Run pending migrations
  down, rollback  Rollback last migration group
  status          Show migration status
  create <name>   Create new migration files
  lock            Acquire migration lock
  unlock          Release migration lock

Environment:
  DATABASE_URL    Database connection string (default: sqlite://auth.db)
                  Examples:
                    sqlite://auth.db
                    postgres://user:pass@localhost:5432/dbname?sslmode=disable`)
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
