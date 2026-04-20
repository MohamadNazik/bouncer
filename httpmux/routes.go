package httpmux

import (
	"net/http"

	internalhttp "github.com/lsflk/bouncer/internal/http"
	"github.com/lsflk/bouncer"
)

// MuxAdapter holds the internal HTTP handler configurations securely.
type MuxAdapter struct {
	handler internalhttp.Handler
}

// New creates a new Mux adapter statefully bound to the Bouncer Authorizer.
func New(authorizer bouncer.Authorizer) *MuxAdapter {
	return &MuxAdapter{
		handler: *internalhttp.NewHandler(authorizer),
	}
}

// RegisterRoutes safely attaches Bouncer authorization endpoints to a multiplexer.
func (a *MuxAdapter) RegisterRoutes(mux *http.ServeMux) error {
	mux.HandleFunc("POST /v1/permissions/check", a.handler.HandleCheck)
	mux.HandleFunc("POST /v1/permissions/grant", a.handler.HandleGrant)
	mux.HandleFunc("POST /v1/permissions/revoke", a.handler.HandleRevoke)
	return nil
}
