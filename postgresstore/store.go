package postgresstore

import (
	"context"
	"database/sql"

	"github.com/lsflk/bouncer/internal/storage/postgres"
)

// PostgresStore implements the bouncer.Store interface using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// New creates a new PostgreSQL store backed by the provided database connection.
func New(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// HasPermission checks if a subject has a permission on a resource.
func (s *PostgresStore) HasPermission(ctx context.Context, subjectID string, resourceID string, permission string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, postgres.QueryHasPermission, subjectID, resourceID, permission).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// GrantPermission grants a permission to a subject on a resource.
// If the permission already exists, it is silently ignored.
func (s *PostgresStore) GrantPermission(ctx context.Context, subjectID string, resourceID string, permission string) error {
	_, err := s.db.ExecContext(ctx, postgres.QueryGrantPermission, subjectID, resourceID, permission)
	return err
}

// RevokePermission removes a permission from a subject on a resource.
func (s *PostgresStore) RevokePermission(ctx context.Context, subjectID string, resourceID string, permission string) error {
	_, err := s.db.ExecContext(ctx, postgres.QueryRevokePermission, subjectID, resourceID, permission)
	return err
}
