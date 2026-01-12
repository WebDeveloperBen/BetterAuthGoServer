package migrate

import "github.com/webdeveloperben/BetterAuthGoServer/db"

// Dialect represents the database dialect.
// Re-exported from db package for convenience.
type Dialect = db.Dialect

// Dialect constants re-exported for convenience.
const (
	DialectPostgres = db.DialectPostgres
	DialectSQLite   = db.DialectSQLite
	DialectMySQL    = db.DialectMySQL
)
