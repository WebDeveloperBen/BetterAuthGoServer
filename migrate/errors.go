package migrate

import (
	"errors"
	"fmt"
)

var (
	// ErrDependencyCycle is returned when plugin dependencies form a cycle.
	ErrDependencyCycle = errors.New("dependency cycle detected")

	// ErrMissingDependency is returned when a plugin depends on a source
	// that was not provided.
	ErrMissingDependency = errors.New("missing dependency")

	// ErrUnsupportedDialect is returned when an unsupported database dialect is used.
	ErrUnsupportedDialect = errors.New("unsupported dialect")

	// ErrDirtyMigration is returned when a previous migration failed partway through.
	ErrDirtyMigration = errors.New("dirty migration state")
)

// MigrationError provides detailed information about a migration failure.
type MigrationError struct {
	// Source is the name of the migration source that failed (e.g., "oauth").
	Source string

	// Version is the migration version that failed.
	Version uint

	// Direction is "up" or "down".
	Direction string

	// Err is the underlying error.
	Err error
}

func (e *MigrationError) Error() string {
	return fmt.Sprintf("migration %s/%d %s failed: %v", e.Source, e.Version, e.Direction, e.Err)
}

func (e *MigrationError) Unwrap() error {
	return e.Err
}

// DependencyError provides details about dependency resolution failures.
type DependencyError struct {
	Source     string
	Dependency string
	Err        error
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("source %q depends on %q: %v", e.Source, e.Dependency, e.Err)
}

func (e *DependencyError) Unwrap() error {
	return e.Err
}
