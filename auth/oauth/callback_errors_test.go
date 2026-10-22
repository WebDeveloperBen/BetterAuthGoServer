package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"golang.org/x/oauth2"
)

func TestErrorCode_EveryFlowErrorHasOneStableCode(t *testing.T) {
	tests := []struct {
		err    error
		code   string
		status int
	}{
		{ErrProviderAccessDenied, CodeAccessDenied, http.StatusBadRequest},
		{ErrProviderError, CodeProviderError, http.StatusBadRequest},
		{fmt.Errorf("%w: failed to exchange code: %w", ErrProviderError, errors.New("invalid_grant")), CodeProviderError, http.StatusBadRequest},
		{ErrNoUserInfo, CodeProviderError, http.StatusBadRequest},
		{ErrStateNotFound, CodeInvalidState, http.StatusBadRequest},
		{ErrStateExpired, CodeInvalidState, http.StatusBadRequest},
		{ErrStateMismatch, CodeInvalidState, http.StatusBadRequest},
		{ErrMissingCode, CodeInvalidCallback, http.StatusBadRequest},
		{ErrProviderNotFound, CodeProviderNotFound, http.StatusBadRequest},
		{ErrRedirectNotAllowed, CodeInvalidRedirect, http.StatusBadRequest},
		{ErrEmailNotVerified, CodeEmailNotVerified, http.StatusForbidden},
		{ErrAccountExistsLinkRequired, CodeAccountExistsLinkRequired, http.StatusConflict},
		{ErrAccountAlreadyLinked, CodeAccountAlreadyLinked, http.StatusConflict},
		{ErrLinkRequiresSession, CodeLinkSessionMismatch, http.StatusForbidden},
		{ErrLinkNotAllowed, CodeLinkSessionMismatch, http.StatusForbidden},
		{models.ErrUserBanned, CodeUserBanned, http.StatusForbidden},
		{fmt.Errorf("failed to get state: %w", errors.New("db down")), CodeServerError, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			assert.Equal(t, tt.code, errorCode(tt.err))
			assert.Equal(t, tt.status, statusForError(tt.err))
		})
	}
}

func TestWriteError_NeverLeaksWrappedDetail(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("%w: failed to exchange code: %w", ErrProviderError, errors.New("client secret rejected"))
	writeError(rec, statusForError(err), err)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"error": ErrProviderError.Error(), "code": CodeProviderError}, body)
}

func TestWithCallbackErrorRedirect_Validation(t *testing.T) {
	valid := []string{
		"/login",
		"/login?next=%2Fdash",
		"https://app.example.com/login",
		"http://localhost:3000/login?a=b",
	}
	for _, target := range valid {
		t.Run("valid "+target, func(t *testing.T) {
			p := (&Plugin{}).WithCallbackErrorRedirect(target)
			require.NoError(t, p.configErr)
			require.NotNil(t, p.callbackErrorRedirect)
			require.NoError(t, p.Init(plugin.Context{}))
		})
	}

	invalid := []string{
		"",
		"login",
		"//evil.example.com/login",
		"/\\evil.example.com",
		"javascript:alert(1)",
		"ftp://example.com/login",
		"https://",
		"https://user:pass@example.com/login",
		"mailto:someone@example.com",
		"/login\r\nSet-Cookie: x=y",
	}
	for _, target := range invalid {
		t.Run(fmt.Sprintf("invalid %q", target), func(t *testing.T) {
			p := (&Plugin{}).WithCallbackErrorRedirect(target)
			assert.Nil(t, p.callbackErrorRedirect)
			require.ErrorIs(t, p.Init(plugin.Context{}), ErrInvalidCallbackErrorRedirect)
		})
	}

	// A later valid target replaces an earlier invalid one.
	p := (&Plugin{}).WithCallbackErrorRedirect("javascript:alert(1)").WithCallbackErrorRedirect("/login")
	require.NoError(t, p.Init(plugin.Context{}))
}

func failFlowLocation(t *testing.T, p *Plugin, provider string, isLink bool, err error) *url.URL {
	t.Helper()
	rec := httptest.NewRecorder()
	p.failFlow(rec, httptest.NewRequest(http.MethodGet, "/oauth/x/callback", nil), provider, isLink, err)
	require.Equal(t, http.StatusFound, rec.Code)
	location, parseErr := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, parseErr)
	return location
}

func TestFailFlow_RedirectsWithCodeProviderAndFlow(t *testing.T) {
	p := (&Plugin{}).WithCallbackErrorRedirect("/login?next=%2Fdash")

	location := failFlowLocation(t, p, "github", true, ErrAccountAlreadyLinked)
	assert.Equal(t, "/login", location.Path)
	assert.Equal(t, url.Values{
		"next":     {"/dash"},
		"error":    {CodeAccountAlreadyLinked},
		"provider": {"github"},
		"flow":     {"link"},
	}, location.Query())

	// Internal errors redirect with server_error; an empty provider is omitted.
	location = failFlowLocation(t, p, "", false, errors.New("db password rejected"))
	assert.Equal(t, url.Values{"next": {"/dash"}, "error": {CodeServerError}}, location.Query())
}

func TestFailFlow_AbsoluteTarget(t *testing.T) {
	p := (&Plugin{}).WithCallbackErrorRedirect("https://app.example.com/login")
	location := failFlowLocation(t, p, "google", false, ErrProviderAccessDenied)
	assert.Equal(t, "https://app.example.com/login?error=access_denied&provider=google", location.String())
}

func TestFailFlow_JSONWithoutOption(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Plugin{}).failFlow(rec, httptest.NewRequest(http.MethodGet, "/oauth/x/callback", nil), "x", true, ErrStateExpired)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"error": ErrStateExpired.Error(), "code": CodeInvalidState}, body)
}

func TestService_Discard(t *testing.T) {
	service, store := newLinkTestService(t)
	userID, sessionID := "user-1", "session-1"
	store.states["link-state"] = &State{
		State: "link-state", Provider: "test", ExpiresAt: time.Now().Add(time.Minute),
		LinkUserID: &userID, LinkSessionID: &sessionID,
	}
	store.states["other-state"] = &State{State: "other-state", Provider: "github", ExpiresAt: time.Now().Add(time.Minute)}

	_, err := service.Discard(context.Background(), "unknown", "link-state")
	require.ErrorIs(t, err, ErrProviderNotFound)

	state, err := service.Discard(context.Background(), "test", "link-state")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.IsLink())
	assert.NotContains(t, store.states, "link-state", "the state must be consumed")

	// States of other providers and unknown or empty states are left alone.
	for _, value := range []string{"other-state", "missing", ""} {
		state, err = service.Discard(context.Background(), "test", value)
		require.NoError(t, err)
		assert.Nil(t, state)
	}
	assert.Contains(t, store.states, "other-state")
}

func TestService_Complete_ExchangeFailureReturnsStateAndProviderError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	service, store := newLinkTestService(t)
	service.RegisterProvider(&mockProvider{
		name:   "failing",
		config: &oauth2.Config{ClientID: "client-id", Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL}},
	})
	userID, sessionID := "user-1", "session-1"
	store.states["link-state"] = &State{
		State: "link-state", Provider: "failing", ExpiresAt: time.Now().Add(time.Minute),
		LinkUserID: &userID, LinkSessionID: &sessionID,
	}

	_, state, err := service.Complete(context.Background(), "failing", "code", "link-state")
	require.ErrorIs(t, err, ErrProviderError)
	require.NotNil(t, state)
	assert.True(t, state.IsLink())
}
