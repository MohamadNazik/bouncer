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
// It accepts a variadic list of middlewares that are applied to each route.
func (a *MuxAdapter) RegisterRoutes(mux *http.ServeMux, mw ...func(http.Handler) http.Handler) error {
	checkHandler := a.applyMiddlewares(http.HandlerFunc(a.handler.HandleCheck), mw)
	grantHandler := a.applyMiddlewares(http.HandlerFunc(a.handler.HandleGrant), mw)
	revokeHandler := a.applyMiddlewares(http.HandlerFunc(a.handler.HandleRevoke), mw)

	mux.Handle("POST /v1/permissions/check", checkHandler)
	mux.Handle("POST /v1/permissions/grant", grantHandler)
	mux.Handle("POST /v1/permissions/revoke", revokeHandler)

	return nil
}

// applyMiddlewares wraps the handler with the given middlewares.
// Middlewares are applied in the order they are provided (outermost to innermost).
func (a *MuxAdapter) applyMiddlewares(h http.Handler, mw []func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
