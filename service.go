package bouncer

import (
	"github.com/lsflk/bouncer/internal/authorization"
)

// New creates a new Bouncer Authorizer instance powered by the provided store.
func New(store Store) Authorizer {
	return authorization.NewService(store)
}
