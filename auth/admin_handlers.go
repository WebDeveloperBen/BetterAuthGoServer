package auth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// AdminListUsersRequest represents query parameters for listing users
type AdminListUsersRequest struct {
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Query  string `json:"query"`
	Role   string `json:"role"`
}

// AdminListUsersResponse represents the response for listing users
type AdminListUsersResponse struct {
	Users []*UserResponse `json:"users"`
	Total int64           `json:"total"`
}

// AdminBanRequest represents the request body for banning a user
type AdminBanRequest struct {
	Reason string `json:"reason"`
}

// AdminSetRoleRequest represents the request body for setting user role
type AdminSetRoleRequest struct {
	Role string `json:"role"`
}

// AdminUpdateUserRequest represents the request body for updating a user
type AdminUpdateUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
}

// handleAdminListUsers handles GET /admin/users
func (a *Auth) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	adminStore, ok := a.store.(AdminStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, ErrAdminNotSupported)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	opts := ListUsersOptions{
		Offset: offset,
		Limit:  limit,
		Query:  query.Get("query"),
		Role:   query.Get("role"),
	}

	result, err := adminStore.ListUsers(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	users := make([]*UserResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = toUserResponse(u)
	}

	writeJSON(w, http.StatusOK, AdminListUsersResponse{
		Users: users,
		Total: result.Total,
	})
}

// handleAdminGetUser handles GET /admin/users/{id}
func (a *Auth) handleAdminGetUser(w http.ResponseWriter, r *http.Request, userID string) {
	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// handleAdminUpdateUser handles PATCH /admin/users/{id}
func (a *Auth) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request, userID string) {
	var req AdminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Apply updates
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		user.Email = *req.Email
		user.EmailVerified = false // Reset verification on email change
	}
	if req.Role != nil {
		user.Role = *req.Role
	}

	if err := a.store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// handleAdminDeleteUser handles DELETE /admin/users/{id}
func (a *Auth) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Delete all user sessions
	if err := a.store.DeleteSessionsByUserID(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Delete all user accounts
	if err := a.store.DeleteAccountsByUserID(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Delete the user
	if err := a.store.DeleteUser(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleAdminBanUser handles POST /admin/users/{id}/ban
func (a *Auth) handleAdminBanUser(w http.ResponseWriter, r *http.Request, userID string) {
	adminStore, ok := a.store.(AdminStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, ErrAdminNotSupported)
		return
	}

	var req AdminBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// Verify user exists
	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Ban the user
	if err := adminStore.BanUser(r.Context(), userID, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Revoke all sessions
	if err := a.store.DeleteSessionsByUserID(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleAdminUnbanUser handles POST /admin/users/{id}/unban
func (a *Auth) handleAdminUnbanUser(w http.ResponseWriter, r *http.Request, userID string) {
	adminStore, ok := a.store.(AdminStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, ErrAdminNotSupported)
		return
	}

	// Verify user exists
	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Unban the user
	if err := adminStore.UnbanUser(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleAdminSetRole handles POST /admin/users/{id}/role
func (a *Auth) handleAdminSetRole(w http.ResponseWriter, r *http.Request, userID string) {
	adminStore, ok := a.store.(AdminStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, ErrAdminNotSupported)
		return
	}

	var req AdminSetRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	if req.Role == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// Verify user exists
	user, err := a.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, ErrUserNotFound)
		return
	}

	// Set the role
	if err := adminStore.SetUserRole(r.Context(), userID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RequireAdmin returns middleware that requires the user to have admin role
func (a *Auth) RequireAdmin(next http.Handler) http.Handler {
	return a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
			return
		}

		// Check if user has admin role
		if user.Role != "admin" {
			writeError(w, http.StatusForbidden, ErrForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}))
}

// parseAdminUserPath extracts the user ID and optional action from the path
// Supports: /admin/users/{id}, /admin/users/{id}/ban, /admin/users/{id}/unban, /admin/users/{id}/role
func parseAdminUserPath(path string) (userID string, action string) {
	path = strings.TrimPrefix(path, "/admin/users/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", ""
	}
	userID = parts[0]
	if len(parts) > 1 {
		action = parts[1]
	}
	return userID, action
}

// ==================== Self-Service Profile Endpoints ====================

// ProfileUpdateRequest represents the request body for updating own profile
type ProfileUpdateRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
}

// AccountResponse represents an OAuth account in API responses
type AccountResponse struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
}

// handleGetProfile handles GET /profile
func (a *Auth) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// handleUpdateProfile handles PATCH /profile
func (a *Auth) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	var req ProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// Apply updates
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Image != nil {
		user.Image = req.Image
	}

	if err := a.store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// handleDeleteAccount handles DELETE /account (delete own account)
func (a *Auth) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	// Delete all user sessions
	if err := a.store.DeleteSessionsByUserID(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Delete all user accounts
	if err := a.store.DeleteAccountsByUserID(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Delete the user
	if err := a.store.DeleteUser(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear session cookie
	a.ClearSessionCookie(w)

	w.WriteHeader(http.StatusNoContent)
}

// handleListAccounts handles GET /accounts (list linked OAuth accounts)
func (a *Auth) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	accounts, err := a.store.ListAccountsByUserID(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	response := make([]*AccountResponse, 0, len(accounts))
	for _, acc := range accounts {
		// Only include OAuth accounts (not email/password)
		if acc.Provider != ProviderEmail {
			response = append(response, &AccountResponse{
				ID:       acc.ID,
				Provider: string(acc.Provider),
			})
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// handleUnlinkAccount handles DELETE /accounts/:provider (unlink OAuth account)
func (a *Auth) handleUnlinkAccount(w http.ResponseWriter, r *http.Request, provider string) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	// Get all accounts to check we're not removing the last one
	accounts, err := a.store.ListAccountsByUserID(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Find the account to remove
	var accountToRemove *Account
	for _, acc := range accounts {
		if string(acc.Provider) == provider {
			accountToRemove = acc
			break
		}
	}

	if accountToRemove == nil {
		writeError(w, http.StatusNotFound, ErrAccountNotFound)
		return
	}

	// Check that we're not removing the only authentication method
	if len(accounts) <= 1 {
		writeError(w, http.StatusBadRequest, ErrCannotUnlinkLastAccount)
		return
	}

	// Delete the account
	if err := a.store.DeleteAccount(r.Context(), accountToRemove.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
