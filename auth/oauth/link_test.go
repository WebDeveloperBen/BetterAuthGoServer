package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
	"golang.org/x/oauth2"
)

func newLinkTestService(t *testing.T) (*Service, *mockStateStore) {
	t.Helper()
	store := newMockStateStore()
	service := NewService(store,
		token.NewHasher("test-secret-32-bytes-minimum!!!"),
		token.NewEncryptor("test-secret-32-bytes-minimum!!!"),
	)
	service.RegisterProvider(&mockProvider{
		name: "test",
		config: &oauth2.Config{
			ClientID: "client-id",
			Endpoint: oauth2.Endpoint{AuthURL: "https://auth.example.com/authorize"},
		},
	})
	return service, store
}

func TestService_Begin_IsNotLink(t *testing.T) {
	service, store := newLinkTestService(t)

	result, err := service.Begin(context.Background(), "test", "")
	require.NoError(t, err)

	state := store.states[result.State]
	require.NotNil(t, state)
	assert.False(t, state.IsLink())
	assert.Nil(t, state.LinkUserID)
	assert.Nil(t, state.LinkSessionID)
}

func TestService_BeginLink_BindsUserAndSession(t *testing.T) {
	service, store := newLinkTestService(t)

	result, err := service.BeginLink(context.Background(), "test", "/settings", "user-1", "session-1")
	require.NoError(t, err)

	state := store.states[result.State]
	require.NotNil(t, state)
	assert.True(t, state.IsLink())
	require.NotNil(t, state.LinkUserID)
	require.NotNil(t, state.LinkSessionID)
	assert.Equal(t, "user-1", *state.LinkUserID)
	assert.Equal(t, "session-1", *state.LinkSessionID)
	require.NotNil(t, state.RedirectTo)
	assert.Equal(t, "/settings", *state.RedirectTo)
}

func TestService_BeginLink_RequiresUserAndSession(t *testing.T) {
	service, store := newLinkTestService(t)

	_, err := service.BeginLink(context.Background(), "test", "", "user-1", "")
	require.ErrorIs(t, err, ErrLinkRequiresSession)

	_, err = service.BeginLink(context.Background(), "test", "", "", "session-1")
	require.ErrorIs(t, err, ErrLinkRequiresSession)

	assert.Empty(t, store.states)
}

func TestState_IsLink_PartialBindingCountsAsLink(t *testing.T) {
	userID := "user-1"
	assert.True(t, (&State{LinkUserID: &userID}).IsLink(), "a partially bound state must never fall back to sign-in")
}

func TestStatusForError(t *testing.T) {
	assert.Equal(t, http.StatusForbidden, statusForError(ErrEmailNotVerified))
	assert.Equal(t, http.StatusForbidden, statusForError(ErrLinkRequiresSession))
	assert.Equal(t, http.StatusForbidden, statusForError(ErrLinkNotAllowed))
	assert.Equal(t, http.StatusForbidden, statusForError(models.ErrUserBanned))
	assert.Equal(t, http.StatusConflict, statusForError(ErrAccountExistsLinkRequired))
	assert.Equal(t, http.StatusConflict, statusForError(ErrAccountAlreadyLinked))
	assert.Equal(t, http.StatusInternalServerError, statusForError(errors.New("db down")))
}

func TestWriteError_IncludesStableCode(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{ErrEmailNotVerified, CodeEmailNotVerified},
		{ErrAccountExistsLinkRequired, CodeAccountExistsLinkRequired},
		{ErrAccountAlreadyLinked, CodeAccountAlreadyLinked},
		{ErrLinkRequiresSession, CodeLinkSessionMismatch},
		{models.ErrUserBanned, CodeUserBanned},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(rec, statusForError(tt.err), tt.err)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, tt.code, body["code"])
			assert.Equal(t, tt.err.Error(), body["error"])
		})
	}

	rec := httptest.NewRecorder()
	writeError(rec, http.StatusInternalServerError, errors.New("secret detail"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, http.StatusText(http.StatusInternalServerError), body["error"])
	assert.NotContains(t, body, "code")
}
