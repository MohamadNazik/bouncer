package bouncer

import (
	"github.com/lsflk/bouncer/internal/authorization"
)

// New creates a new Bouncer Authorizer instance powered by the provided store and optional configurations.
func New(store Store, opts ...Option) Authorizer {
	cfg := &Config{}
	for _, opt := range opts {
		opt(cfg)
	}

	return authorization.NewService(store, cfg.Logger)
}
