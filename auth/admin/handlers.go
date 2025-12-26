package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

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

type impersonateUserRequest struct {
	UserID string `json:"userId"`
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

type impersonationResponse struct {
	Session sessionResponse `json:"session"`
	User    *userResponse   `json:"user"`
}

type sessionResponse struct {
	ID        string  `json:"id"`
	UserID    string  `json:"userId"`
	ExpiresAt string  `json:"expiresAt"`
	IPAddress *string `json:"ipAddress,omitempty"`
	UserAgent *string `json:"userAgent,omitempty"`
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
	service      AdminOperations
	auth         plugin.AuthCore
	sessions     plugin.SessionManager
	userProvider UserProvider
	config       *Config
}

func newHandlers(service AdminOperations, auth plugin.AuthCore, sessions plugin.SessionManager, userProvider UserProvider, config *Config) *handlers {
	return &handlers{
		service:      service,
		auth:         auth,
		sessions:     sessions,
		userProvider: userProvider,
		config:       config,
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

	user, err := h.service.UpdateUser(r.Context(), userID, AdminUserUpdates(req))
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

// impersonateUser handles POST /admin/impersonate-user
func (h *handlers) impersonateUser(w http.ResponseWriter, r *http.Request) {
	var req impersonateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, errors.New("userId is required"))
		return
	}

	// Get the current admin user
	adminUser, err := h.userProvider.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrImpersonationNotAllowed)
		return
	}

	// Check if user has impersonation permission
	if h.config.AccessControl != nil {
		hasPermission := h.config.AccessControl.UserHasPermission(adminUser.Role, map[string][]string{
			"user": {"impersonate"},
		})
		if !hasPermission {
			writeError(w, http.StatusForbidden, ErrImpersonationNotAllowed)
			return
		}
	}

	// Get the target user
	targetUser, err := h.userProvider.GetPluginUser(r.Context(), req.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Check if target is an admin (and if we're allowed to impersonate admins)
	if !h.config.AllowImpersonatingAdmins {
		isTargetAdmin := false
		for _, adminRole := range h.config.AdminRoles {
			if targetUser.Role == adminRole {
				isTargetAdmin = true
				break
			}
		}
		if isTargetAdmin {
			writeError(w, http.StatusForbidden, ErrCannotImpersonateAdmins)
			return
		}
	}

	// Get current session to verify user is authenticated
	currentSession := h.sessions.GetFromRequest(r)
	if currentSession == nil {
		writeError(w, http.StatusUnauthorized, ErrImpersonationNotAllowed)
		return
	}

	// Get the current session token (we need to store this for restoration)
	adminSessionToken := h.sessions.GetSessionToken(r)
	if adminSessionToken == "" {
		writeError(w, http.StatusUnauthorized, ErrImpersonationNotAllowed)
		return
	}

	// Create impersonation session
	impersonationSession, err := h.sessions.CreateWithImpersonation(
		r.Context(),
		targetUser.ID,
		adminUser.ID,
		r,
		h.config.ImpersonationSessionDuration,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to create impersonation session"))
		return
	}

	// Store the admin's original session token for restoration
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session_token",
		Value:    adminSessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.ImpersonationSessionDuration.Seconds()),
	})

	// Set the impersonation session cookie
	h.sessions.SetSessionCookie(w, impersonationSession.RawToken, impersonationSession.ExpiresAt)

	writeJSON(w, http.StatusOK, impersonationResponse{
		Session: sessionResponse{
			ID:        impersonationSession.ID,
			UserID:    impersonationSession.UserID,
			ExpiresAt: impersonationSession.ExpiresAt.Format("2006-01-02T15:04:05Z"),
			IPAddress: impersonationSession.IPAddress,
			UserAgent: impersonationSession.UserAgent,
		},
		User: &userResponse{
			ID:            targetUser.ID,
			Email:         targetUser.Email,
			EmailVerified: targetUser.EmailVerified,
			Name:          targetUser.Name,
			Image:         targetUser.Image,
			Role:          targetUser.Role,
			Banned:        targetUser.Banned,
			CreatedAt:     targetUser.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:     targetUser.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
	})
}

// stopImpersonating handles POST /admin/stop-impersonating
func (h *handlers) stopImpersonating(w http.ResponseWriter, r *http.Request) {
	// Get current session
	currentSession := h.sessions.GetFromRequest(r)
	if currentSession == nil {
		writeError(w, http.StatusUnauthorized, ErrNotImpersonating)
		return
	}

	// Check if this is an impersonation session
	if !currentSession.IsImpersonation() {
		writeError(w, http.StatusBadRequest, ErrNotImpersonating)
		return
	}

	// Get the admin's original session token from cookie
	adminTokenCookie, err := r.Cookie("admin_session_token")
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrImpersonationSessionInvalid)
		return
	}

	// Delete the impersonation session
	if err := h.sessions.Delete(r.Context(), currentSession.ID); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to delete impersonation session"))
		return
	}

	// Clear the admin_session_token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete the cookie
	})

	// Restore the admin's original session
	// Use a reasonable expiration (24 hours from now) since we don't have the original expiry
	h.sessions.SetSessionCookie(w, adminTokenCookie.Value, time.Now().Add(24*time.Hour))

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Impersonation ended. Original admin session restored.",
	})
}
