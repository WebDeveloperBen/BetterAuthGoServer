package apikey

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// handlers contains HTTP handlers for the API key plugin.
type handlers struct {
	service *Service
	auth    AuthProvider
	config  *Config
}

func newHandlers(service *Service, auth AuthProvider, config *Config) *handlers {
	return &handlers{
		service: service,
		auth:    auth,
		config:  config,
	}
}

// Response types

type createAPIKeyRequest struct {
	Name        *string     `json:"name,omitempty"`
	Prefix      *string     `json:"prefix,omitempty"`
	ExpiresIn   *int64      `json:"expiresIn,omitempty"`
	Permissions Permissions `json:"permissions,omitempty"`
	Metadata    Metadata    `json:"metadata,omitempty"`

	RateLimitEnabled    *bool  `json:"rateLimitEnabled,omitempty"`
	RateLimitTimeWindow *int64 `json:"rateLimitTimeWindow,omitempty"`
	RateLimitMax        *int   `json:"rateLimitMax,omitempty"`

	Remaining      *int   `json:"remaining,omitempty"`
	RefillInterval *int64 `json:"refillInterval,omitempty"`
	RefillAmount   *int   `json:"refillAmount,omitempty"`
}

type createAPIKeyResponse struct {
	Key    *apiKeyResponse `json:"key"`
	RawKey string          `json:"rawKey"`
}

type apiKeyResponse struct {
	ID                  string      `json:"id"`
	Name                *string     `json:"name,omitempty"`
	Start               string      `json:"start"`
	Prefix              *string     `json:"prefix,omitempty"`
	UserID              string      `json:"userId"`
	RateLimitEnabled    bool        `json:"rateLimitEnabled"`
	RateLimitTimeWindow int64       `json:"rateLimitTimeWindow,omitempty"`
	RateLimitMax        int         `json:"rateLimitMax,omitempty"`
	Remaining           *int        `json:"remaining,omitempty"`
	RefillInterval      *int64      `json:"refillInterval,omitempty"`
	RefillAmount        *int        `json:"refillAmount,omitempty"`
	Enabled             bool        `json:"enabled"`
	ExpiresAt           *string     `json:"expiresAt,omitempty"`
	Permissions         Permissions `json:"permissions,omitempty"`
	Metadata            Metadata    `json:"metadata,omitempty"`
	CreatedAt           string      `json:"createdAt"`
	UpdatedAt           string      `json:"updatedAt"`
}

type verifyAPIKeyRequest struct {
	Key         string      `json:"key"`
	Permissions Permissions `json:"permissions,omitempty"`
}

type verifyAPIKeyResponse struct {
	Valid   bool            `json:"valid"`
	Error   *string         `json:"error,omitempty"`
	Message *string         `json:"message,omitempty"`
	Key     *apiKeyResponse `json:"key,omitempty"`
}

type updateAPIKeyRequest struct {
	KeyID               string  `json:"keyId"`
	Name                *string `json:"name,omitempty"`
	Enabled             *bool   `json:"enabled,omitempty"`
	RateLimitEnabled    *bool   `json:"rateLimitEnabled,omitempty"`
	RateLimitTimeWindow *int64  `json:"rateLimitTimeWindow,omitempty"`
	RateLimitMax        *int    `json:"rateLimitMax,omitempty"`
	Remaining           *int    `json:"remaining,omitempty"`
	RefillInterval      *int64  `json:"refillInterval,omitempty"`
	RefillAmount        *int    `json:"refillAmount,omitempty"`
	ExpiresIn           *int64  `json:"expiresIn,omitempty"`
}

type deleteAPIKeyRequest struct {
	KeyID string `json:"keyId"`
}

type getAPIKeyRequest struct {
	KeyID string `json:"keyId"`
}

type deleteAllExpiredResponse struct {
	Deleted int64 `json:"deleted"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{
		Error:   code,
		Message: message,
	})
}

func toAPIKeyResponse(key *APIKey, service *Service) *apiKeyResponse {
	resp := &apiKeyResponse{
		ID:                  key.ID,
		Name:                key.Name,
		Start:               key.Start,
		Prefix:              key.Prefix,
		UserID:              key.UserID,
		RateLimitEnabled:    key.RateLimitEnabled,
		RateLimitTimeWindow: key.RateLimitTimeWindow,
		RateLimitMax:        key.RateLimitMax,
		Remaining:           key.Remaining,
		RefillInterval:      key.RefillInterval,
		RefillAmount:        key.RefillAmount,
		Enabled:             key.Enabled,
		CreatedAt:           key.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:           key.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if key.ExpiresAt != nil {
		exp := key.ExpiresAt.Format("2006-01-02T15:04:05Z")
		resp.ExpiresAt = &exp
	}

	// Parse permissions and metadata
	if perms, err := service.GetPermissions(key); err == nil && perms != nil {
		resp.Permissions = perms
	}
	if meta, err := service.GetMetadata(key); err == nil && meta != nil {
		resp.Metadata = meta
	}

	return resp
}

// Handlers

func (h *handlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	result, err := h.service.Create(r.Context(), user.ID, CreateRequest(req))
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidPrefix):
			writeError(w, http.StatusBadRequest, "INVALID_PREFIX", "Invalid prefix length")
		case errors.Is(err, ErrInvalidName):
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "Invalid name length")
		default:
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create API key")
		}
		return
	}

	writeJSON(w, http.StatusOK, createAPIKeyResponse{
		Key:    toAPIKeyResponse(result.Key, h.service),
		RawKey: result.RawKey,
	})
}

func (h *handlers) handleList(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	keys, err := h.service.List(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list API keys")
		return
	}

	response := make([]*apiKeyResponse, len(keys))
	for i, key := range keys {
		response[i] = toAPIKeyResponse(key, h.service)
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *handlers) handleGet(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req getAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	key, err := h.service.GetByIDAndUser(r.Context(), req.KeyID, user.ID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			writeError(w, http.StatusNotFound, ErrCodeKeyNotFound, "API key not found")
		} else {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get API key")
		}
		return
	}

	writeJSON(w, http.StatusOK, toAPIKeyResponse(key, h.service))
}

func (h *handlers) handleUpdate(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req updateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	key, err := h.service.Update(r.Context(), req.KeyID, user.ID, UpdateRequest{
		Name:                req.Name,
		Enabled:             req.Enabled,
		RateLimitEnabled:    req.RateLimitEnabled,
		RateLimitTimeWindow: req.RateLimitTimeWindow,
		RateLimitMax:        req.RateLimitMax,
		Remaining:           req.Remaining,
		RefillInterval:      req.RefillInterval,
		RefillAmount:        req.RefillAmount,
		ExpiresIn:           req.ExpiresIn,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrKeyNotFound):
			writeError(w, http.StatusNotFound, ErrCodeKeyNotFound, "API key not found")
		case errors.Is(err, ErrInvalidName):
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "Invalid name length")
		default:
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update API key")
		}
		return
	}

	writeJSON(w, http.StatusOK, toAPIKeyResponse(key, h.service))
}

func (h *handlers) handleDelete(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	var req deleteAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if err := h.service.Delete(r.Context(), req.KeyID, user.ID); err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			writeError(w, http.StatusNotFound, ErrCodeKeyNotFound, "API key not found")
		} else {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete API key")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *handlers) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, verifyAPIKeyResponse{
			Valid:   false,
			Error:   stringPtr(ErrCodeInvalidKey),
			Message: stringPtr("Invalid request body"),
		})
		return
	}

	if req.Key == "" {
		writeJSON(w, http.StatusOK, verifyAPIKeyResponse{
			Valid:   false,
			Error:   stringPtr(ErrCodeInvalidKey),
			Message: stringPtr("API key is required"),
		})
		return
	}

	key, err := h.service.VerifyKey(r.Context(), req.Key, req.Permissions)
	if err != nil {
		resp := verifyAPIKeyResponse{Valid: false}

		var rateLimitErr *RateLimitError
		switch {
		case errors.Is(err, ErrInvalidAPIKey):
			resp.Error = stringPtr(ErrCodeInvalidKey)
			resp.Message = stringPtr("Invalid API key")
		case errors.Is(err, ErrExpiredAPIKey):
			resp.Error = stringPtr(ErrCodeExpiredKey)
			resp.Message = stringPtr("API key has expired")
		case errors.Is(err, ErrDisabledAPIKey):
			resp.Error = stringPtr(ErrCodeDisabledKey)
			resp.Message = stringPtr("API key is disabled")
		case errors.As(err, &rateLimitErr):
			resp.Error = stringPtr(ErrCodeRateLimited)
			resp.Message = stringPtr(rateLimitErr.Error())
			w.Header().Set("Retry-After", rateLimitErr.RetryAfter.String())
		case errors.Is(err, ErrNoRemainingUses):
			resp.Error = stringPtr(ErrCodeNoRemaining)
			resp.Message = stringPtr("No remaining uses")
		case errors.Is(err, ErrInsufficientPerms):
			resp.Error = stringPtr(ErrCodeInsufficientPerms)
			resp.Message = stringPtr("Insufficient permissions")
		default:
			resp.Error = stringPtr("INTERNAL_ERROR")
			resp.Message = stringPtr("Verification failed")
		}

		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Call hook
	if h.config.OnAPIKeyVerified != nil {
		h.config.OnAPIKeyVerified(key, r)
	}

	writeJSON(w, http.StatusOK, verifyAPIKeyResponse{
		Valid: true,
		Key:   toAPIKeyResponse(key, h.service),
	})
}

func (h *handlers) handleDeleteAllExpired(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	deleted, err := h.service.DeleteAllExpired(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete expired keys")
		return
	}

	writeJSON(w, http.StatusOK, deleteAllExpiredResponse{Deleted: deleted})
}

// handleDynamicRoute handles routes with path parameters like /api-key/{id}
func (h *handlers) handleDynamicRoute(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api-key/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api-key/")
	if path == "" || strings.Contains(path, "/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Route not found")
		return
	}

	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		key, err := h.service.GetByIDAndUser(r.Context(), path, user.ID)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) {
				writeError(w, http.StatusNotFound, ErrCodeKeyNotFound, "API key not found")
			} else {
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get API key")
			}
			return
		}
		writeJSON(w, http.StatusOK, toAPIKeyResponse(key, h.service))

	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

func stringPtr(s string) *string {
	return &s
}
