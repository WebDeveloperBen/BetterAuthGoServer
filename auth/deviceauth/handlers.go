package deviceauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Request/response types

type deviceCodeRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceTokenRequest struct {
	GrantType  string `json:"grant_type"`
	DeviceCode string `json:"device_code"`
	ClientID   string `json:"client_id"`
}

type userResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
}

type sessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type tokenSuccessResponse struct {
	User    userResponse    `json:"user"`
	Session sessionResponse `json:"session"`
}

type oauth2ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type verifyResponse struct {
	Valid     bool    `json:"valid"`
	Status    string  `json:"status"`
	ClientID  *string `json:"clientId,omitempty"`
	Scope     *string `json:"scope,omitempty"`
	ExpiresAt string  `json:"expiresAt,omitempty"`
}

type approveRequest struct {
	UserCode string `json:"user_code"`
}

type denyRequest struct {
	UserCode string `json:"user_code"`
}

type successResponse struct {
	Success bool `json:"success"`
}

// handlers holds the HTTP handlers for device authorization.
type handlers struct {
	service *Service
	auth    AuthProvider
}

func newHandlers(service *Service, auth AuthProvider) *handlers {
	return &handlers{
		service: service,
		auth:    auth,
	}
}

// handleDeviceCode handles POST /device/code
// This is the first step where a device requests authorization codes.
func (h *handlers) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	var req deviceCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidRequest, "Invalid request body")
		return
	}

	result, err := h.service.CreateDeviceCode(r.Context(), CreateDeviceCodeRequest(req))

	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidClient, "Invalid client")
			return
		}
		writeOAuth2Error(w, http.StatusInternalServerError, OAuth2ErrorInvalidRequest, "Failed to create device code")
		return
	}

	setCacheControl(w)
	writeJSON(w, http.StatusOK, deviceCodeResponse{
		DeviceCode:              result.DeviceCode,
		UserCode:                result.UserCode,
		VerificationURI:         result.VerificationURI,
		VerificationURIComplete: result.VerificationURIComplete,
		ExpiresIn:               result.ExpiresIn,
		Interval:                result.Interval,
	})
}

// handleDeviceToken handles POST /device/token
// This is called by the device to poll for an access token.
func (h *handlers) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var req deviceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidRequest, "Invalid request body")
		return
	}

	// Validate grant type
	if req.GrantType != DeviceCodeGrantType {
		writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidGrant, "Invalid grant type")
		return
	}

	if req.DeviceCode == "" {
		writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidRequest, "Missing device_code")
		return
	}

	result, err := h.service.CheckToken(r.Context(), req.DeviceCode, req.ClientID)
	if err != nil {
		setCacheControl(w)

		switch {
		case errors.Is(err, ErrAuthorizationPending):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorAuthorizationPending, "Authorization pending")
		case errors.Is(err, ErrSlowDown):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorSlowDown, "Polling too frequently")
		case errors.Is(err, ErrAccessDenied):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorAccessDenied, "Access denied")
		case errors.Is(err, ErrExpiredDeviceCode):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorExpiredToken, "Device code expired")
		case errors.Is(err, ErrInvalidClient):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidClient, "Invalid client")
		case errors.Is(err, ErrInvalidDeviceCode):
			writeOAuth2Error(w, http.StatusBadRequest, OAuth2ErrorInvalidGrant, "Invalid device code")
		default:
			writeOAuth2Error(w, http.StatusInternalServerError, OAuth2ErrorInvalidRequest, "Internal error")
		}
		return
	}

	// Device code was approved - create session for the user
	session, err := h.auth.CreateSessionForUser(r.Context(), result.UserID, r)
	if err != nil {
		writeOAuth2Error(w, http.StatusInternalServerError, OAuth2ErrorInvalidRequest, "Failed to create session")
		return
	}

	// Get user details
	user, err := h.auth.GetPluginUser(r.Context(), result.UserID)
	if err != nil {
		writeOAuth2Error(w, http.StatusInternalServerError, OAuth2ErrorInvalidRequest, "Failed to get user")
		return
	}

	setCacheControl(w)
	writeJSON(w, http.StatusOK, tokenSuccessResponse{
		User: userResponse{
			ID:            user.ID,
			Email:         user.Email,
			Name:          user.Name,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt,
		},
		Session: sessionResponse{
			ID:        session.ID,
			ExpiresAt: session.ExpiresAt,
		},
	})
}

// handleVerify handles GET /device/verify
// This is used by the verification page to check if a user code is valid.
func (h *handlers) handleVerify(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		writeJSON(w, http.StatusBadRequest, verifyResponse{
			Valid: false,
		})
		return
	}

	dc, err := h.service.GetByUserCode(r.Context(), userCode)
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{
			Valid: false,
		})
		return
	}

	setCacheControl(w)
	writeJSON(w, http.StatusOK, verifyResponse{
		Valid:     true,
		Status:    string(dc.Status),
		ClientID:  dc.ClientID,
		Scope:     dc.Scope,
		ExpiresAt: dc.ExpiresAt.Format(time.RFC3339),
	})
}

// handleApprove handles POST /device/approve
// This is called when an authenticated user approves a device authorization.
func (h *handlers) handleApprove(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, ErrAuthenticationRequired)
		return
	}

	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.UserCode == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing user_code"))
		return
	}

	err = h.service.Approve(r.Context(), req.UserCode, user.ID)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidUserCode):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, ErrExpiredUserCode):
			writeError(w, http.StatusGone, err)
		case errors.Is(err, ErrAlreadyProcessed):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	writeJSON(w, http.StatusOK, successResponse{Success: true})
}

// handleDeny handles POST /device/deny
// This is called to deny a device authorization request.
func (h *handlers) handleDeny(w http.ResponseWriter, r *http.Request) {
	var req denyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.UserCode == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing user_code"))
		return
	}

	err := h.service.Deny(r.Context(), req.UserCode)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidUserCode):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, ErrExpiredUserCode):
			writeError(w, http.StatusGone, err)
		case errors.Is(err, ErrAlreadyProcessed):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	writeJSON(w, http.StatusOK, successResponse{Success: true})
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = http.StatusText(status)
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeOAuth2Error(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, oauth2ErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	})
}

func setCacheControl(w http.ResponseWriter) {
	// RFC 8628 requires Cache-Control: no-store
	w.Header().Set("Cache-Control", "no-store")
}
