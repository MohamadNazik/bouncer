package http

import (
	"encoding/json"
	"net/http"

	"github.com/lsflk/bouncer"
)

type Handler struct {
	authorizer bouncer.Authorizer
}

func NewHandler(authorizer bouncer.Authorizer) *Handler {
	return &Handler{authorizer: authorizer}
}

// PermissionRequest represents the standard JSON payload for authorization APIs.
type PermissionRequest struct {
	SubjectID  string `json:"subject_id"`
	ResourceID string `json:"resource_id"`
	Permission string `json:"permission"`
}

// HandleCheck processes requests to check if a subject has a permission.
func (h *Handler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	var req PermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid block payload", http.StatusBadRequest)
		return
	}

	allowed, err := h.authorizer.HasPermission(r.Context(), req.SubjectID, req.ResourceID, req.Permission)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if allowed {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	} else {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
	}
}

// HandleGrant processes requests to grant a permission.
func (h *Handler) HandleGrant(w http.ResponseWriter, r *http.Request) {
	var req PermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid block payload", http.StatusBadRequest)
		return
	}

	err := h.authorizer.GrantPermission(r.Context(), req.SubjectID, req.ResourceID, req.Permission)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleRevoke processes requests to revoke a permission.
func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	var req PermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid block payload", http.StatusBadRequest)
		return
	}

	err := h.authorizer.RevokePermission(r.Context(), req.SubjectID, req.ResourceID, req.Permission)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
