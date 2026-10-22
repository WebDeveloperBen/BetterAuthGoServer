package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type sqlStateError string

func (e sqlStateError) Error() string    { return "pq: error " + string(e) }
func (e sqlStateError) SQLState() string { return string(e) }

func TestIsUniqueViolation(t *testing.T) {
	assert.True(t, IsUniqueViolation(DialectPostgres, fmt.Errorf("insert: %w", sqlStateError("23505"))))
	assert.False(t, IsUniqueViolation(DialectPostgres, sqlStateError("23503")))
	assert.False(t, IsUniqueViolation(DialectPostgres, errors.New("duplicate key value")))

	assert.True(t, IsUniqueViolation(DialectMySQL, errors.New("Error 1062 (23000): Duplicate entry 'x' for key 'uq'")))
	assert.False(t, IsUniqueViolation(DialectMySQL, errors.New("Error 1452 (23000): Cannot add or update a child row")))

	assert.True(t, IsUniqueViolation(DialectSQLite, errors.New("UNIQUE constraint failed: oauth_accounts.provider, oauth_accounts.provider_account_id")))
	assert.False(t, IsUniqueViolation(DialectSQLite, errors.New("FOREIGN KEY constraint failed")))

	assert.False(t, IsUniqueViolation(DialectPostgres, nil))
}

func TestIsDeadlock(t *testing.T) {
	assert.True(t, IsDeadlock(DialectPostgres, sqlStateError("40P01")))
	assert.True(t, IsDeadlock(DialectPostgres, sqlStateError("40001")))
	assert.False(t, IsDeadlock(DialectPostgres, sqlStateError("23505")))

	assert.True(t, IsDeadlock(DialectMySQL, errors.New("Error 1213 (40001): Deadlock found when trying to get lock; try restarting transaction")))
	assert.False(t, IsDeadlock(DialectMySQL, errors.New("Error 1062 (23000): Duplicate entry")))

	assert.False(t, IsDeadlock(DialectSQLite, errors.New("database is locked")))
	assert.False(t, IsDeadlock(DialectMySQL, nil))
}
