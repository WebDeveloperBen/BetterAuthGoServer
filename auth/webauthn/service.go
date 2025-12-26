package webauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"time"

	libwebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
	"log/slog"
)

const (
	sessionTypeRegister = "register"
	sessionTypeLogin    = "login"
)

// Service handles WebAuthn flows and persistence.
type Service struct {
	webauthn  *libwebauthn.WebAuthn
	store     *Store
	encryptor *token.Encryptor
	config    Config
	logger    *slog.Logger
}

// NewService creates a new WebAuthn service.
func NewService(store *Store, encryptor *token.Encryptor, config Config, logger *slog.Logger) (*Service, error) {
	waConfig := buildLibraryConfig(config)
	wa, err := libwebauthn.New(waConfig)
	if err != nil {
		return nil, err
	}

	return &Service{
		webauthn:  wa,
		store:     store,
		encryptor: encryptor,
		config:    config,
		logger:    logger,
	}, nil
}

// BeginRegistration starts a WebAuthn registration flow.
func (s *Service) BeginRegistration(ctx context.Context, user *plugin.User) (any, *WebAuthnSession, error) {
	if user == nil {
		return nil, nil, ErrInvalidRequest
	}

	webUser, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	options, sessionData, err := s.webauthn.BeginRegistration(webUser)
	if err != nil {
		return nil, nil, err
	}

	session, err := s.createSession(ctx, &user.ID, sessionTypeRegister, sessionData)
	if err != nil {
		return nil, nil, err
	}

	return options, session, nil
}

// FinishRegistration completes a WebAuthn registration flow.
func (s *Service) FinishRegistration(ctx context.Context, user *plugin.User, sessionID string, r *http.Request) (*WebAuthnCredential, error) {
	if user == nil || sessionID == "" {
		return nil, ErrInvalidRequest
	}

	session, sessionData, err := s.getSessionData(ctx, sessionID, sessionTypeRegister)
	if err != nil {
		return nil, err
	}

	credential, err := s.webauthn.FinishRegistration(s.webAuthnUser(user, nil), *sessionData, r)
	if err != nil {
		return nil, err
	}

	credentialID := credentialBytesField(credential, "ID")
	if len(credentialID) == 0 {
		return nil, ErrInvalidResponse
	}

	existing, err := s.store.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrInvalidResponse
	}

	publicKey := credentialBytesField(credential, "PublicKey")
	signCount := credentialSignCount(credential)
	if len(credentialID) == 0 || len(publicKey) == 0 {
		return nil, ErrInvalidResponse
	}

	record := &WebAuthnCredential{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    signCount,
		Transports:   credentialTransports(credential),
		CreatedAt:    time.Now(),
	}

	if err := s.store.CreateCredential(ctx, record); err != nil {
		return nil, err
	}

	_ = s.store.DeleteSession(ctx, session.ID)
	return record, nil
}

// BeginLogin starts a WebAuthn login flow.
func (s *Service) BeginLogin(ctx context.Context, user *plugin.User) (any, *WebAuthnSession, error) {
	if user == nil {
		return nil, nil, ErrInvalidRequest
	}

	webUser, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	if len(webUser.credentials) == 0 {
		return nil, nil, ErrCredentialNotFound
	}

	options, sessionData, err := s.webauthn.BeginLogin(webUser)
	if err != nil {
		return nil, nil, err
	}

	session, err := s.createSession(ctx, &user.ID, sessionTypeLogin, sessionData)
	if err != nil {
		return nil, nil, err
	}

	return options, session, nil
}

// FinishLogin completes a WebAuthn login flow.
func (s *Service) FinishLogin(ctx context.Context, user *plugin.User, sessionID string, r *http.Request) (*WebAuthnCredential, error) {
	if user == nil || sessionID == "" {
		return nil, ErrInvalidRequest
	}

	session, sessionData, err := s.getSessionData(ctx, sessionID, sessionTypeLogin)
	if err != nil {
		return nil, err
	}

	webUser, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}

	credential, err := s.webauthn.FinishLogin(webUser, *sessionData, r)
	if err != nil {
		return nil, err
	}

	credentialID := credentialBytesField(credential, "ID")
	if len(credentialID) == 0 {
		return nil, ErrInvalidResponse
	}

	record, err := s.store.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrCredentialNotFound
	}

	now := time.Now()
	signCount := credentialSignCount(credential)
	if err := s.store.UpdateCredentialSignCount(ctx, record.ID, signCount, now); err != nil {
		return nil, err
	}

	_ = s.store.DeleteSession(ctx, session.ID)
	return record, nil
}

func (s *Service) createSession(ctx context.Context, userID *string, sessionType string, sessionData *libwebauthn.SessionData) (*WebAuthnSession, error) {
	sessionID, err := token.Generate()
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sessionData)
	if err != nil {
		return nil, err
	}

	if s.encryptor != nil {
		ciphertext, err := s.encryptor.Encrypt(string(payload))
		if err != nil {
			return nil, err
		}
		payload = []byte(ciphertext)
	}

	now := time.Now()
	expiresAt := now.Add(s.sessionTimeout())
	session := &WebAuthnSession{
		ID:        sessionID,
		UserID:    userID,
		Type:      sessionType,
		Data:      payload,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := s.store.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (s *Service) getSessionData(ctx context.Context, sessionID string, sessionType string) (*WebAuthnSession, *libwebauthn.SessionData, error) {
	record, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	if record == nil {
		return nil, nil, ErrSessionNotFound
	}
	if record.Type != sessionType {
		return nil, nil, ErrInvalidRequest
	}
	if record.IsExpired() {
		_ = s.store.DeleteSession(ctx, record.ID)
		return nil, nil, ErrSessionExpired
	}

	payload := record.Data
	if s.encryptor != nil {
		plaintext, err := s.encryptor.Decrypt(string(record.Data))
		if err != nil {
			return nil, nil, err
		}
		payload = []byte(plaintext)
	}

	var sessionData libwebauthn.SessionData
	if err := json.Unmarshal(payload, &sessionData); err != nil {
		return nil, nil, err
	}

	return record, &sessionData, nil
}

func (s *Service) sessionTimeout() time.Duration {
	if s.config.Timeout > 0 {
		return s.config.Timeout
	}
	return 5 * time.Minute
}

func (s *Service) loadWebAuthnUser(ctx context.Context, user *plugin.User) (*webauthnUser, error) {
	credentials, err := s.store.ListCredentialsByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	webCreds := make([]libwebauthn.Credential, 0, len(credentials))
	for _, credential := range credentials {
		webCreds = append(webCreds, credentialFromModel(credential))
	}

	return &webauthnUser{
		user:        user,
		credentials: webCreds,
	}, nil
}

func (s *Service) webAuthnUser(user *plugin.User, credentials []libwebauthn.Credential) *webauthnUser {
	return &webauthnUser{
		user:        user,
		credentials: credentials,
	}
}

// webauthnUser adapts plugin.User to the WebAuthn library interface.
type webauthnUser struct {
	user        *plugin.User
	credentials []libwebauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	if u.user == nil {
		return nil
	}
	return []byte(u.user.ID)
}

func (u *webauthnUser) WebAuthnName() string {
	if u.user == nil {
		return ""
	}
	return u.user.Email
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.user == nil {
		return ""
	}
	return u.user.Name
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []libwebauthn.Credential {
	return u.credentials
}

func credentialFromModel(model *WebAuthnCredential) libwebauthn.Credential {
	cred := libwebauthn.Credential{}
	setCredentialBytesField(&cred, "ID", model.CredentialID)
	setCredentialBytesField(&cred, "PublicKey", model.PublicKey)
	setCredentialSignCount(&cred, model.SignCount)

	setCredentialTransports(&cred, model.Transports)
	return cred
}

func credentialTransports(cred *libwebauthn.Credential) []string {
	if cred == nil {
		return nil
	}

	value := reflect.Indirect(reflect.ValueOf(cred))
	field := value.FieldByName("Transport")
	if !field.IsValid() {
		field = value.FieldByName("Transports")
	}
	if !field.IsValid() || field.Kind() != reflect.Slice {
		return nil
	}

	transports := make([]string, 0, field.Len())
	for i := 0; i < field.Len(); i++ {
		item := field.Index(i).Interface()
		transports = append(transports, formatTransport(item))
	}

	return transports
}

func setCredentialTransports(cred *libwebauthn.Credential, transports []string) {
	if cred == nil || len(transports) == 0 {
		return
	}

	value := reflect.ValueOf(cred).Elem()
	field := value.FieldByName("Transport")
	if !field.IsValid() {
		field = value.FieldByName("Transports")
	}
	if !field.IsValid() || field.Kind() != reflect.Slice || !field.CanSet() {
		return
	}

	slice := reflect.MakeSlice(field.Type(), len(transports), len(transports))
	for i, transport := range transports {
		elem := slice.Index(i)
		if elem.Kind() == reflect.String {
			elem.SetString(transport)
			continue
		}
		if elem.CanSet() {
			elem.Set(reflect.ValueOf(transport).Convert(elem.Type()))
		}
	}
	field.Set(slice)
}

func formatTransport(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

func credentialBytesField(cred *libwebauthn.Credential, name string) []byte {
	if cred == nil {
		return nil
	}

	value := reflect.Indirect(reflect.ValueOf(cred))
	field := value.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Slice {
		return nil
	}
	if field.Type().Elem().Kind() != reflect.Uint8 {
		return nil
	}

	bytes := make([]byte, field.Len())
	reflect.Copy(reflect.ValueOf(bytes), field)
	return bytes
}

func setCredentialBytesField(cred *libwebauthn.Credential, name string, value []byte) {
	if cred == nil || value == nil {
		return
	}

	v := reflect.ValueOf(cred).Elem()
	field := v.FieldByName(name)
	if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.Slice {
		return
	}
	if field.Type().Elem().Kind() != reflect.Uint8 {
		return
	}

	bytes := make([]byte, len(value))
	copy(bytes, value)
	field.Set(reflect.ValueOf(bytes))
}

func credentialSignCount(cred *libwebauthn.Credential) uint32 {
	if cred == nil {
		return 0
	}

	value := reflect.Indirect(reflect.ValueOf(cred))
	authenticator := value.FieldByName("Authenticator")
	if !authenticator.IsValid() {
		return 0
	}
	if authenticator.Kind() == reflect.Ptr {
		if authenticator.IsNil() {
			return 0
		}
		authenticator = authenticator.Elem()
	}
	signCount := authenticator.FieldByName("SignCount")
	if !signCount.IsValid() {
		return 0
	}
	switch signCount.Kind() {
	case reflect.Uint32, reflect.Uint, reflect.Uint64, reflect.Uint16, reflect.Uint8:
		return uint32(signCount.Uint())
	default:
		return 0
	}
}

func setCredentialSignCount(cred *libwebauthn.Credential, count uint32) {
	if cred == nil {
		return
	}

	value := reflect.ValueOf(cred).Elem()
	authenticator := value.FieldByName("Authenticator")
	if !authenticator.IsValid() || !authenticator.CanSet() {
		return
	}
	if authenticator.Kind() == reflect.Ptr {
		if authenticator.IsNil() {
			authenticator.Set(reflect.New(authenticator.Type().Elem()))
		}
		authenticator = authenticator.Elem()
	}
	signCount := authenticator.FieldByName("SignCount")
	if !signCount.IsValid() || !signCount.CanSet() {
		return
	}
	switch signCount.Kind() {
	case reflect.Uint32, reflect.Uint, reflect.Uint64, reflect.Uint16, reflect.Uint8:
		signCount.SetUint(uint64(count))
	}
}

func applyBaseURLDefaults(config *Config) {
	if config == nil || config.BaseURL == "" {
		return
	}

	parsed, err := url.Parse(config.BaseURL)
	if err != nil {
		return
	}

	host := parsed.Hostname()
	if config.RPID == "" {
		config.RPID = host
	}
	if config.RPDisplayName == "" {
		config.RPDisplayName = host
	}
	if len(config.RPOrigins) == 0 && parsed.Scheme != "" && parsed.Host != "" {
		config.RPOrigins = []string{parsed.Scheme + "://" + parsed.Host}
	}
}

func buildLibraryConfig(config Config) *libwebauthn.Config {
	cfg := &libwebauthn.Config{}
	setConfigField(cfg, "RPDisplayName", config.RPDisplayName)
	setConfigField(cfg, "RPID", config.RPID)
	setConfigField(cfg, "RPOrigins", config.RPOrigins)
	if len(config.RPOrigins) == 1 {
		setConfigField(cfg, "RPOrigin", config.RPOrigins[0])
	}
	setConfigField(cfg, "Debug", config.Debug)
	return cfg
}

func setConfigField(cfg *libwebauthn.Config, name string, value any) {
	if cfg == nil {
		return
	}
	if value == nil {
		return
	}
	v := reflect.ValueOf(cfg).Elem()
	field := v.FieldByName(name)
	if !field.IsValid() || !field.CanSet() {
		return
	}
	val := reflect.ValueOf(value)
	if val.Type().AssignableTo(field.Type()) {
		field.Set(val)
		return
	}
	if val.Type().ConvertibleTo(field.Type()) {
		field.Set(val.Convert(field.Type()))
	}
}
