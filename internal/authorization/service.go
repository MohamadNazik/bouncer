package authorization

import (
	"context"

	"github.com/lsflk/bouncer/internal/permission"
	"github.com/lsflk/bouncer/internal/resource"
	"github.com/lsflk/bouncer/internal/subject"
)

// Expected store interface internally (matches pkg/bouncer.Store)
type Store interface {
	HasPermission(ctx context.Context, subjectID string, resourceID string, permission string) (bool, error)
	GrantPermission(ctx context.Context, subjectID string, resourceID string, permission string) error
	RevokePermission(ctx context.Context, subjectID string, resourceID string, permission string) error
}

// Service provides authorization capabilities by interacting with the storage layer.
type Service struct {
	store Store
}

// NewService creates a new Service instance backed by the provided store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// HasPermission checks if the subject has the requested permission on the resource.
func (s *Service) HasPermission(ctx context.Context, subjectStr string, resourceStr string, permissionStr string) (bool, error) {
	subID := subject.ID(subjectStr)
	resID := resource.ID(resourceStr)
	permName := permission.Name(permissionStr)

	return s.store.HasPermission(ctx, string(subID), string(resID), string(permName))
}

// GrantPermission grants the requested permission on the resource to the subject.
func (s *Service) GrantPermission(ctx context.Context, subjectStr string, resourceStr string, permissionStr string) error {
	subID := subject.ID(subjectStr)
	resID := resource.ID(resourceStr)
	permName := permission.Name(permissionStr)

	return s.store.GrantPermission(ctx, string(subID), string(resID), string(permName))
}

// RevokePermission revokes the requested permission on the resource from the subject.
func (s *Service) RevokePermission(ctx context.Context, subjectStr string, resourceStr string, permissionStr string) error {
	subID := subject.ID(subjectStr)
	resID := resource.ID(resourceStr)
	permName := permission.Name(permissionStr)

	return s.store.RevokePermission(ctx, string(subID), string(resID), string(permName))
}
