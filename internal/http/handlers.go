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

// ResourceRequest represents the JSON payload for resource management APIs.
type ResourceRequest struct {
	ResourceID string  `json:"resource_id"`
	Name       string  `json:"name"`
	ParentID   *string `json:"parent_id,omitempty"`
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


// HandleCreateResource processes requests to register a new resource.
func (h *Handler) HandleCreateResource(w http.ResponseWriter, r *http.Request) {
	var req ResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := h.authorizer.CreateResource(r.Context(), req.ResourceID, req.Name, req.ParentID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// HandleDeleteResource processes requests to remove a resource.
func (h *Handler) HandleDeleteResource(w http.ResponseWriter, r *http.Request) {
	resourceID := r.URL.Query().Get("resource_id")
	if resourceID == "" {
		// Fallback to body if query param is missing
		var req ResourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			resourceID = req.ResourceID
		}
	}

	if resourceID == "" {
		http.Error(w, "Missing resource_id", http.StatusBadRequest)
		return
	}

	err := h.authorizer.DeleteResource(r.Context(), resourceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

