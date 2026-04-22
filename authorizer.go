package bouncer

import "context"

// Authorizer represents the main entrypoint for checking and managing permissions.
type Authorizer interface {
	HasPermission(ctx context.Context, subjectID string, resourceID string, permission string) (bool, error)
	GrantPermission(ctx context.Context, subjectID string, resourceID string, permission string) error
	RevokePermission(ctx context.Context, subjectID string, resourceID string, permission string) error
}

// Store represents the persistence layer required by the Authorizer.
type Store interface {
	HasPermission(ctx context.Context, subjectID string, resourceID string, permission string) (bool, error)
	GrantPermission(ctx context.Context, subjectID string, resourceID string, permission string) error
	RevokePermission(ctx context.Context, subjectID string, resourceID string, permission string) error
	CreateResource(ctx context.Context, resourceID string, name string, parentID *string) error
	DeleteResource(ctx context.Context, resourceID string) error
}
