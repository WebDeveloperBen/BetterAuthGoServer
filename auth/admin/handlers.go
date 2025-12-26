package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Request types

type banRequest struct {
	Reason string `json:"reason"`
}

type setRoleRequest struct {
	Role string `json:"role"`
}

type updateUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
}

type hasPermissionRequest struct {
	UserID      *string             `json:"userId,omitempty"`
	Role        *string             `json:"role,omitempty"`
	Permissions map[string][]string `json:"permissions,omitempty"`
}

type checkRolePermissionRequest struct {
	Role        string              `json:"role"`
	Permissions map[string][]string `json:"permissions"`
}

// Response types

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type userResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          string  `json:"name"`
	Image         *string `json:"image,omitempty"`
	Banned        bool    `json:"banned"`
	BanReason     *string `json:"ban_reason,omitempty"`
	Role          string  `json:"role"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type listUsersResponse struct {
	Users []*userResponse `json:"users"`
	Total int64           `json:"total"`
}

type permissionResponse struct {
	HasPermission bool `json:"hasPermission"`
}

// toUserResponse converts a models.User to userResponse
func toUserResponse(u *models.User) *userResponse {
	if u == nil {
		return nil
	}
	return &userResponse{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		Role:          u.Role,
		CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{
		Error:   http.StatusText(status),
		Message: err.Error(),
	})
}

// decodeJSON decodes a JSON request body
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// handlers holds the admin handlers with access to the service
type handlers struct {
	service AdminOperations
	auth    plugin.AuthCore
	config  *Config
}

func newHandlers(service AdminOperations, auth plugin.AuthCore, config *Config) *handlers {
	return &handlers{
		service: service,
		auth:    auth,
		config:  config,
	}
}

// listUsers handles GET /admin/users
func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))

	opts := ListUsersOptions{
		Offset: offset,
		Limit:  limit,
		Query:  query.Get("query"),
		Role:   query.Get("role"),
	}

	result, err := h.service.ListUsers(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	users := make([]*userResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = toUserResponse(u)
	}

	writeJSON(w, http.StatusOK, listUsersResponse{
		Users: users,
		Total: result.Total,
	})
}

// getUser handles GET /admin/users/{id}
func (h *handlers) getUser(w http.ResponseWriter, r *http.Request, userID string) {
	user, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// updateUser handles PATCH /admin/users/{id}
func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request, userID string) {
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	user, err := h.service.UpdateUser(r.Context(), userID, AdminUserUpdates{
		Name:  req.Name,
		Email: req.Email,
		Role:  req.Role,
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// deleteUser handles DELETE /admin/users/{id}
func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	err := h.service.DeleteUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// banUser handles POST /admin/users/{id}/ban
func (h *handlers) banUser(w http.ResponseWriter, r *http.Request, userID string) {
	var req banRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	err := h.service.BanUser(r.Context(), userID, req.Reason)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// unbanUser handles POST /admin/users/{id}/unban
func (h *handlers) unbanUser(w http.ResponseWriter, r *http.Request, userID string) {
	err := h.service.UnbanUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// setRole handles POST /admin/users/{id}/role
func (h *handlers) setRole(w http.ResponseWriter, r *http.Request, userID string) {
	var req setRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	err := h.service.SetUserRole(r.Context(), userID, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, ErrInvalidRequest):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// hasPermission handles POST /admin/permissions/has-permission
func (h *handlers) hasPermission(w http.ResponseWriter, r *http.Request) {
	var req hasPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	var hasPermission bool
	var err error

	if h.config.AccessControl == nil {
		writeError(w, http.StatusInternalServerError, errors.New("access control not configured"))
		return
	}

	if req.UserID != nil {
		// Check permission for a specific user
		user, userErr := h.service.GetUser(r.Context(), *req.UserID)
		if userErr != nil {
			if errors.Is(userErr, ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
			} else {
				writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
			}
			return
		}
		hasPermission = h.config.AccessControl.UserHasPermission(user.Role, req.Permissions)
	} else if req.Role != nil {
		// Check permission for a role
		hasPermission, err = h.config.AccessControl.HasPermissions(*req.Role, req.Permissions)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, errors.New("either userId or role must be provided"))
		return
	}

	writeJSON(w, http.StatusOK, permissionResponse{HasPermission: hasPermission})
}

// checkRolePermission handles POST /admin/permissions/check-role
func (h *handlers) checkRolePermission(w http.ResponseWriter, r *http.Request) {
	var req checkRolePermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if h.config.AccessControl == nil {
		writeError(w, http.StatusInternalServerError, errors.New("access control not configured"))
		return
	}

	role, err := h.config.AccessControl.GetRole(req.Role)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("role not found"))
		return
	}

	hasPermission := role.CheckRolePermission(req.Permissions)

	writeJSON(w, http.StatusOK, permissionResponse{HasPermission: hasPermission})
}
