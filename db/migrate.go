package db

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed schema/postgres/001_users.sql
var pgUsers string

//go:embed schema/postgres/002_accounts.sql
var pgAccounts string

//go:embed schema/postgres/003_sessions.sql
var pgSessions string

//go:embed schema/postgres/004_verifications.sql
var pgVerifications string

//go:embed schema/sqlite/001_users.sql
var sqliteUsers string

//go:embed schema/sqlite/002_accounts.sql
var sqliteAccounts string

//go:embed schema/sqlite/003_sessions.sql
var sqliteSessions string

//go:embed schema/sqlite/004_verifications.sql
var sqliteVerifications string

// Migrate creates all required database tables if they don't exist.
// Uses the embedded schema SQL files.
func (s *Store) Migrate(ctx context.Context) error {
	var schemas []string

	if s.dialect == DialectPostgres {
		schemas = []string{pgUsers, pgAccounts, pgSessions, pgVerifications}
	} else {
		schemas = []string{sqliteUsers, sqliteAccounts, sqliteSessions, sqliteVerifications}
	}

	for _, schema := range schemas {
		// Execute each statement separately
		statements := splitStatements(schema)
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("failed to execute migration: %w", err)
			}
		}
	}

	return nil
}

// splitStatements splits SQL into individual statements.
// Handles semicolons properly.
func splitStatements(sql string) []string {
	var statements []string
	var current strings.Builder

	for line := range strings.SplitSeq(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")

		if strings.HasSuffix(trimmed, ";") {
			statements = append(statements, current.String())
			current.Reset()
		}
	}

	// Add any remaining content
	if remaining := strings.TrimSpace(current.String()); remaining != "" {
		statements = append(statements, remaining)
	}

	return statements
}
