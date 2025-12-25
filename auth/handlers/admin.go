package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Request types

type adminBanRequest struct {
	Reason string `json:"reason"`
}

type adminSetRoleRequest struct {
	Role string `json:"role"`
}

type adminUpdateUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
}

// Response types

type adminListUsersResponse struct {
	Users []*UserResponse `json:"users"`
	Total int64           `json:"total"`
}

// AdminListUsers returns a handler for GET /admin/users
func AdminListUsers(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		offset, _ := strconv.Atoi(query.Get("offset"))
		limit, _ := strconv.Atoi(query.Get("limit"))

		opts := models.ListUsersOptions{
			Offset: offset,
			Limit:  limit,
			Query:  query.Get("query"),
			Role:   query.Get("role"),
		}

		result, err := a.ListUsers(r.Context(), opts)
		if err != nil {
			if errors.Is(err, auth.ErrAdminNotSupported) {
				WriteError(w, http.StatusNotImplemented, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		users := make([]*UserResponse, len(result.Users))
		for i, u := range result.Users {
			users[i] = ToUserResponse(u)
		}

		WriteJSON(w, http.StatusOK, adminListUsersResponse{
			Users: users,
			Total: result.Total,
		})
	}
}

// AdminGetUser returns a handler for GET /admin/users/{id}
func AdminGetUser(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		user, err := a.AdminGetUser(r.Context(), userID)
		if err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				WriteError(w, http.StatusNotFound, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		WriteJSON(w, http.StatusOK, ToUserResponse(user))
	}
}

// AdminUpdateUser returns a handler for PATCH /admin/users/{id}
func AdminUpdateUser(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		var req adminUpdateUserRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		user, err := a.AdminUpdateUser(r.Context(), userID, auth.AdminUserUpdates{
			Name:  req.Name,
			Email: req.Email,
			Role:  req.Role,
		})
		if err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				WriteError(w, http.StatusNotFound, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		WriteJSON(w, http.StatusOK, ToUserResponse(user))
	}
}

// AdminDeleteUser returns a handler for DELETE /admin/users/{id}
func AdminDeleteUser(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		err := a.AdminDeleteUser(r.Context(), userID)
		if err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				WriteError(w, http.StatusNotFound, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminBanUser returns a handler for POST /admin/users/{id}/ban
func AdminBanUser(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		var req adminBanRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		err := a.BanUser(r.Context(), userID, req.Reason)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAdminNotSupported):
				WriteError(w, http.StatusNotImplemented, err)
			case errors.Is(err, auth.ErrUserNotFound):
				WriteError(w, http.StatusNotFound, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminUnbanUser returns a handler for POST /admin/users/{id}/unban
func AdminUnbanUser(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		err := a.UnbanUser(r.Context(), userID)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAdminNotSupported):
				WriteError(w, http.StatusNotImplemented, err)
			case errors.Is(err, auth.ErrUserNotFound):
				WriteError(w, http.StatusNotFound, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminSetRole returns a handler for POST /admin/users/{id}/role
func AdminSetRole(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, userID string) {
		var req adminSetRoleRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		err := a.SetUserRole(r.Context(), userID, req.Role)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAdminNotSupported):
				WriteError(w, http.StatusNotImplemented, err)
			case errors.Is(err, auth.ErrUserNotFound):
				WriteError(w, http.StatusNotFound, err)
			case errors.Is(err, auth.ErrInvalidRequest):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// parseAdminUserPath extracts the user ID and optional action from the path
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
