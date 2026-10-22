package db

import (
	"errors"
	"strings"
)

// IsUniqueViolation reports whether err is a unique-constraint violation raised by the
// database of the given dialect. It does not import any driver:
//   - PostgreSQL: SQLSTATE 23505 via the SQLState() method of lib/pq and pgx errors;
//   - MySQL: error 1062 (ER_DUP_ENTRY), as formatted by go-sql-driver/mysql;
//   - SQLite: "UNIQUE constraint failed" (mattn/go-sqlite3 and modernc.org/sqlite).
func IsUniqueViolation(dialect Dialect, err error) bool {
	if err == nil {
		return false
	}
	switch dialect {
	case DialectPostgres:
		var state interface{ SQLState() string }
		return errors.As(err, &state) && state.SQLState() == "23505"
	case DialectMySQL:
		return strings.Contains(err.Error(), "Error 1062")
	case DialectSQLite:
		return strings.Contains(err.Error(), "UNIQUE constraint failed")
	default:
		return false
	}
}

// IsDeadlock reports whether the database aborted the statement or transaction as a
// deadlock or serialization victim, i.e. it can be retried:
//   - PostgreSQL: SQLSTATE 40P01 (deadlock_detected) or 40001 (serialization_failure);
//   - MySQL: error 1213 (ER_LOCK_DEADLOCK), e.g. when several inserts of the same unique
//     key wait on a transaction that rolls back;
//   - SQLite: never (writers are serialised; lock contention surfaces as SQLITE_BUSY).
func IsDeadlock(dialect Dialect, err error) bool {
	if err == nil {
		return false
	}
	switch dialect {
	case DialectPostgres:
		var state interface{ SQLState() string }
		return errors.As(err, &state) && (state.SQLState() == "40P01" || state.SQLState() == "40001")
	case DialectMySQL:
		return strings.Contains(err.Error(), "Error 1213")
	default:
		return false
	}
}
