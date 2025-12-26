package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// setupHandlersTest sets up the test environment for handler tests
func setupHandlersTest(t *testing.T) (*testDB, *organization.Plugin, *mockAuthProvider) {
	t.Helper()

	tdb := setupTestDB(t)

	user := &plugin.User{
		ID:    "test-user-id",
		Email: "test@example.com",
		Name:  "Test User",
	}
	session := &plugin.SessionInfo{
		ID:     "test-session-id",
		UserID: "test-user-id",
	}
	mockAuth := newMockAuthProvider(user, session)

	// Create and initialize the plugin
	p := organization.NewPlugin(
		organization.WithTeams(organization.TeamsConfig{Enabled: true}),
	)

	ctx := plugin.Context{
		DB:      tdb.DB,
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		Auth:    mockAuth,
	}

	if err := p.Init(ctx); err != nil {
		tdb.cleanup(t)
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	return tdb, p, mockAuth
}

func TestHandlers_CreateOrganization(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var createHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization" && r.Method == "POST" {
			createHandler = r.Handler
			break
		}
	}

	if createHandler == nil {
		t.Fatal("Create organization handler not found")
	}

	t.Run("creates organization successfully", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		body := map[string]any{
			"name": "Test Organization",
			"slug": "test-org",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		createHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d. Body: %s", w.Code, http.StatusCreated, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp["name"] != "Test Organization" {
			t.Errorf("name = %v, want %v", resp["name"], "Test Organization")
		}

		if resp["slug"] != "test-org" {
			t.Errorf("slug = %v, want %v", resp["slug"], "test-org")
		}
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")

		body := map[string]any{
			"slug": "test-org",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		createHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("returns error for missing slug", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")

		body := map[string]any{
			"name": "Test Organization",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		createHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestHandlers_ListUserOrganizations(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var listHandler, createHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization" && r.Method == "GET" {
			listHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createHandler = r.Handler
		}
	}

	t.Run("lists user organizations", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create some organizations
		for i := 1; i <= 2; i++ {
			body := map[string]any{
				"name": "Org " + string(rune('0'+i)),
				"slug": "org-" + string(rune('0'+i)),
			}
			jsonBody, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			createHandler(w, req)
		}

		// List organizations
		req := httptest.NewRequest("GET", "/organization", nil)
		w := httptest.NewRecorder()

		listHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", w.Code, http.StatusOK, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		orgs, ok := resp["organizations"].([]any)
		if !ok {
			t.Fatal("Response should contain organizations array")
		}

		if len(orgs) != 2 {
			t.Errorf("len(organizations) = %d, want %d", len(orgs), 2)
		}
	})
}

func TestHandlers_CheckSlug(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var checkSlugHandler, createHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization/check-slug" && r.Method == "GET" {
			checkSlugHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createHandler = r.Handler
		}
	}

	t.Run("returns available for unused slug", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")

		req := httptest.NewRequest("GET", "/organization/check-slug?slug=available-slug", nil)
		w := httptest.NewRecorder()

		checkSlugHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["available"] != true {
			t.Errorf("available = %v, want true", resp["available"])
		}
	})

	t.Run("returns not available for used slug", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization with the slug
		body := map[string]any{"name": "Test Org", "slug": "taken-slug"}
		jsonBody, _ := json.Marshal(body)
		createReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		createReq.Header.Set("Content-Type", "application/json")
		createHandler(httptest.NewRecorder(), createReq)

		// Check if slug is available
		req := httptest.NewRequest("GET", "/organization/check-slug?slug=taken-slug", nil)
		w := httptest.NewRecorder()

		checkSlugHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["available"] != false {
			t.Errorf("available = %v, want false", resp["available"])
		}
	})

	t.Run("returns error for missing slug parameter", func(t *testing.T) {
		tdb.truncateTables(t)

		req := httptest.NewRequest("GET", "/organization/check-slug", nil)
		w := httptest.NewRecorder()

		checkSlugHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestHandlers_ActiveOrganization(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var getActiveHandler, setActiveHandler, createHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization/active" && r.Method == "GET" {
			getActiveHandler = r.Handler
		}
		if r.Path == "/organization/active" && r.Method == "POST" {
			setActiveHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createHandler = r.Handler
		}
	}

	t.Run("sets and gets active organization", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization first
		createBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(createBody)
		createReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		createHandler(createW, createReq)

		var createResp map[string]any
		json.Unmarshal(createW.Body.Bytes(), &createResp)
		orgID := createResp["id"].(string)

		// Set active organization
		setBody := map[string]any{"organizationId": orgID}
		setJsonBody, _ := json.Marshal(setBody)
		setReq := httptest.NewRequest("POST", "/organization/active", bytes.NewReader(setJsonBody))
		setReq.Header.Set("Content-Type", "application/json")
		setW := httptest.NewRecorder()
		setActiveHandler(setW, setReq)

		if setW.Code != http.StatusOK {
			t.Errorf("Set status = %d, want %d. Body: %s", setW.Code, http.StatusOK, setW.Body.String())
		}

		// Get active organization
		getReq := httptest.NewRequest("GET", "/organization/active", nil)
		getW := httptest.NewRecorder()
		getActiveHandler(getW, getReq)

		if getW.Code != http.StatusOK {
			t.Errorf("Get status = %d, want %d. Body: %s", getW.Code, http.StatusOK, getW.Body.String())
		}

		var getResp map[string]any
		json.Unmarshal(getW.Body.Bytes(), &getResp)

		if getResp["id"] != orgID {
			t.Errorf("Active org id = %v, want %v", getResp["id"], orgID)
		}
	})

	t.Run("sets active organization by slug", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization
		createBody := map[string]any{"name": "Test Org", "slug": "test-org-slug"}
		jsonBody, _ := json.Marshal(createBody)
		createReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		createHandler(createW, createReq)

		var createResp map[string]any
		json.Unmarshal(createW.Body.Bytes(), &createResp)
		orgID := createResp["id"].(string)

		// Set active organization by slug
		setBody := map[string]any{"organizationSlug": "test-org-slug"}
		setJsonBody, _ := json.Marshal(setBody)
		setReq := httptest.NewRequest("POST", "/organization/active", bytes.NewReader(setJsonBody))
		setReq.Header.Set("Content-Type", "application/json")
		setW := httptest.NewRecorder()
		setActiveHandler(setW, setReq)

		if setW.Code != http.StatusOK {
			t.Errorf("Set status = %d, want %d. Body: %s", setW.Code, http.StatusOK, setW.Body.String())
		}

		var setResp map[string]any
		json.Unmarshal(setW.Body.Bytes(), &setResp)

		if setResp["id"] != orgID {
			t.Errorf("Response org id = %v, want %v", setResp["id"], orgID)
		}
	})

	t.Run("returns 404 when no active organization", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		req := httptest.NewRequest("GET", "/organization/active", nil)
		w := httptest.NewRecorder()
		getActiveHandler(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestHandlers_Invitations(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var createInvHandler, listInvHandler, createOrgHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization/invitation" && r.Method == "POST" {
			createInvHandler = r.Handler
		}
		if r.Path == "/organization/invitation" && r.Method == "GET" {
			listInvHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createOrgHandler = r.Handler
		}
	}

	t.Run("creates invitation", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization
		orgBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(orgBody)
		orgReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		orgReq.Header.Set("Content-Type", "application/json")
		orgW := httptest.NewRecorder()
		createOrgHandler(orgW, orgReq)

		var orgResp map[string]any
		json.Unmarshal(orgW.Body.Bytes(), &orgResp)
		orgID := orgResp["id"].(string)

		// Create an invitation
		invBody := map[string]any{
			"email":          "invitee@example.com",
			"role":           "member",
			"organizationId": orgID,
		}
		invJsonBody, _ := json.Marshal(invBody)
		invReq := httptest.NewRequest("POST", "/organization/invitation", bytes.NewReader(invJsonBody))
		invReq.Header.Set("Content-Type", "application/json")
		invW := httptest.NewRecorder()
		createInvHandler(invW, invReq)

		if invW.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d. Body: %s", invW.Code, http.StatusCreated, invW.Body.String())
		}

		var invResp map[string]any
		json.Unmarshal(invW.Body.Bytes(), &invResp)

		if invResp["email"] != "invitee@example.com" {
			t.Errorf("email = %v, want %v", invResp["email"], "invitee@example.com")
		}

		if invResp["status"] != "pending" {
			t.Errorf("status = %v, want %v", invResp["status"], "pending")
		}
	})

	t.Run("lists invitations", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization
		orgBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(orgBody)
		orgReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		orgReq.Header.Set("Content-Type", "application/json")
		orgW := httptest.NewRecorder()
		createOrgHandler(orgW, orgReq)

		var orgResp map[string]any
		json.Unmarshal(orgW.Body.Bytes(), &orgResp)
		orgID := orgResp["id"].(string)

		// Create invitations
		for _, email := range []string{"inv1@example.com", "inv2@example.com"} {
			invBody := map[string]any{"email": email, "role": "member", "organizationId": orgID}
			invJsonBody, _ := json.Marshal(invBody)
			invReq := httptest.NewRequest("POST", "/organization/invitation", bytes.NewReader(invJsonBody))
			invReq.Header.Set("Content-Type", "application/json")
			createInvHandler(httptest.NewRecorder(), invReq)
		}

		// List invitations
		listReq := httptest.NewRequest("GET", "/organization/invitation?organizationId="+orgID, nil)
		listW := httptest.NewRecorder()
		listInvHandler(listW, listReq)

		if listW.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", listW.Code, http.StatusOK, listW.Body.String())
		}

		var listResp map[string]any
		json.Unmarshal(listW.Body.Bytes(), &listResp)

		invitations, ok := listResp["invitations"].([]any)
		if !ok {
			t.Fatal("Response should contain invitations array")
		}

		if len(invitations) != 2 {
			t.Errorf("len(invitations) = %d, want %d", len(invitations), 2)
		}
	})
}

func TestHandlers_Teams(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var createTeamHandler, listTeamsHandler, createOrgHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization/team" && r.Method == "POST" {
			createTeamHandler = r.Handler
		}
		if r.Path == "/organization/team" && r.Method == "GET" {
			listTeamsHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createOrgHandler = r.Handler
		}
	}

	t.Run("creates team", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization
		orgBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(orgBody)
		orgReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		orgReq.Header.Set("Content-Type", "application/json")
		orgW := httptest.NewRecorder()
		createOrgHandler(orgW, orgReq)

		var orgResp map[string]any
		json.Unmarshal(orgW.Body.Bytes(), &orgResp)
		orgID := orgResp["id"].(string)

		// Create a team
		teamBody := map[string]any{"name": "Engineering", "organizationId": orgID}
		teamJsonBody, _ := json.Marshal(teamBody)
		teamReq := httptest.NewRequest("POST", "/organization/team", bytes.NewReader(teamJsonBody))
		teamReq.Header.Set("Content-Type", "application/json")
		teamW := httptest.NewRecorder()
		createTeamHandler(teamW, teamReq)

		if teamW.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d. Body: %s", teamW.Code, http.StatusCreated, teamW.Body.String())
		}

		var teamResp map[string]any
		json.Unmarshal(teamW.Body.Bytes(), &teamResp)

		if teamResp["name"] != "Engineering" {
			t.Errorf("name = %v, want %v", teamResp["name"], "Engineering")
		}
	})

	t.Run("lists teams", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization
		orgBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(orgBody)
		orgReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		orgReq.Header.Set("Content-Type", "application/json")
		orgW := httptest.NewRecorder()
		createOrgHandler(orgW, orgReq)

		var orgResp map[string]any
		json.Unmarshal(orgW.Body.Bytes(), &orgResp)
		orgID := orgResp["id"].(string)

		// Create teams
		for _, name := range []string{"Engineering", "Marketing"} {
			teamBody := map[string]any{"name": name, "organizationId": orgID}
			teamJsonBody, _ := json.Marshal(teamBody)
			teamReq := httptest.NewRequest("POST", "/organization/team", bytes.NewReader(teamJsonBody))
			teamReq.Header.Set("Content-Type", "application/json")
			createTeamHandler(httptest.NewRecorder(), teamReq)
		}

		// List teams
		listReq := httptest.NewRequest("GET", "/organization/team?organizationId="+orgID, nil)
		listW := httptest.NewRecorder()
		listTeamsHandler(listW, listReq)

		if listW.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", listW.Code, http.StatusOK, listW.Body.String())
		}

		var listResp map[string]any
		json.Unmarshal(listW.Body.Bytes(), &listResp)

		teams, ok := listResp["teams"].([]any)
		if !ok {
			t.Fatal("Response should contain teams array")
		}

		if len(teams) != 2 {
			t.Errorf("len(teams) = %d, want %d", len(teams), 2)
		}
	})
}

func TestHandlers_Unauthorized(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	// Create plugin with nil user in mock provider
	mockAuth := newMockAuthProvider(nil, nil)

	p := organization.NewPlugin()
	ctx := plugin.Context{
		DB:      tdb.DB,
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		Auth:    mockAuth,
	}

	if err := p.Init(ctx); err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	routes := p.Routes()
	var createHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization" && r.Method == "POST" {
			createHandler = r.Handler
			break
		}
	}

	t.Run("returns 401 for unauthorized user", func(t *testing.T) {
		body := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		createHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

func TestHandlers_GetActiveMember(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	routes := p.Routes()
	var getActiveMemberHandler, createOrgHandler http.HandlerFunc
	for _, r := range routes {
		if r.Path == "/organization/member/active" && r.Method == "GET" {
			getActiveMemberHandler = r.Handler
		}
		if r.Path == "/organization" && r.Method == "POST" {
			createOrgHandler = r.Handler
		}
	}

	t.Run("returns active member", func(t *testing.T) {
		tdb.truncateTables(t)
		tdb.createTestUser(t, "test-user-id", "test@example.com", "Test User")
		tdb.createTestSession(t, "test-session-id", "test-user-id")

		// Create an organization (user becomes owner)
		orgBody := map[string]any{"name": "Test Org", "slug": "test-org"}
		jsonBody, _ := json.Marshal(orgBody)
		orgReq := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
		orgReq.Header.Set("Content-Type", "application/json")
		orgW := httptest.NewRecorder()
		createOrgHandler(orgW, orgReq)

		// Get active member
		req := httptest.NewRequest("GET", "/organization/member/active", nil)
		w := httptest.NewRecorder()
		getActiveMemberHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", w.Code, http.StatusOK, w.Body.String())
		}

		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["userId"] != "test-user-id" {
			t.Errorf("userId = %v, want %v", resp["userId"], "test-user-id")
		}

		if resp["role"] != "owner" {
			t.Errorf("role = %v, want %v", resp["role"], "owner")
		}
	})
}

func TestPlugin_Migrations(t *testing.T) {
	p := organization.NewPlugin(
		organization.WithTeams(organization.TeamsConfig{Enabled: true}),
	)

	migrations := p.Migrations()

	// Should have: Organization, Member, Invitation
	// Plus Team and TeamMember when teams enabled
	// Note: SessionExtension is added via ALTER TABLE in Init(), not here
	expectedCount := 5 // 3 base + 2 team models

	if len(migrations) != expectedCount {
		t.Errorf("len(migrations) = %d, want %d", len(migrations), expectedCount)
	}
}

func TestPlugin_Middleware(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	mockAuth := newMockAuthProvider(&plugin.User{ID: "user-1"}, &plugin.SessionInfo{ID: "session-1", UserID: "user-1"})

	p := organization.NewPlugin()
	ctx := plugin.Context{
		DB:      tdb.DB,
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		Auth:    mockAuth,
	}

	if err := p.Init(ctx); err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	middlewares := p.Middleware()

	if len(middlewares) != 1 {
		t.Errorf("len(middlewares) = %d, want %d", len(middlewares), 1)
	}

	// Verify middleware has correct priority
	if middlewares[0].Priority != 25 {
		t.Errorf("Priority = %d, want %d", middlewares[0].Priority, 25)
	}

	// Test that middleware passes through
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	wrapped := middlewares[0].Handler(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("Handler should be called through middleware")
	}
}

func TestIntegration_FullOrganizationWorkflow(t *testing.T) {
	tdb, p, _ := setupHandlersTest(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	// Setup users
	owner := tdb.createTestUser(t, "owner-id", "owner@example.com", "Owner")
	member := tdb.createTestUser(t, "member-id", "member@example.com", "Member")
	tdb.createTestSession(t, "owner-session", owner.ID)
	tdb.createTestSession(t, "member-session", member.ID)

	routes := p.Routes()
	handlers := make(map[string]http.HandlerFunc)
	for _, r := range routes {
		key := r.Method + " " + r.Path
		handlers[key] = r.Handler
	}

	// 1. Owner creates organization
	createBody := map[string]any{"name": "Acme Corp", "slug": "acme"}
	jsonBody, _ := json.Marshal(createBody)
	req := httptest.NewRequest("POST", "/organization", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers["POST /organization"](w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Create org failed: %s", w.Body.String())
	}

	var orgResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &orgResp)
	orgID := orgResp["id"].(string)

	// 2. Owner sends invitation to member
	invBody := map[string]any{"email": member.Email, "role": "member", "organizationId": orgID}
	invJson, _ := json.Marshal(invBody)
	invReq := httptest.NewRequest("POST", "/organization/invitation", bytes.NewReader(invJson))
	invReq.Header.Set("Content-Type", "application/json")
	invW := httptest.NewRecorder()
	handlers["POST /organization/invitation"](invW, invReq)

	if invW.Code != http.StatusCreated {
		t.Fatalf("Create invitation failed: %s", invW.Body.String())
	}

	var invResp map[string]any
	json.Unmarshal(invW.Body.Bytes(), &invResp)
	invID := invResp["id"].(string)

	// 3. Member accepts invitation (using service directly since handler needs user context switch)
	service := createTestService(t, tdb.DB)
	acceptedMember, err := service.AcceptInvitation(ctx, invID, member.ID)
	if err != nil {
		t.Fatalf("Accept invitation failed: %v", err)
	}

	if acceptedMember.Role != "member" {
		t.Errorf("Accepted member role = %q, want %q", acceptedMember.Role, "member")
	}

	// 4. Owner creates a team
	teamBody := map[string]any{"name": "Engineering", "organizationId": orgID}
	teamJson, _ := json.Marshal(teamBody)
	teamReq := httptest.NewRequest("POST", "/organization/team", bytes.NewReader(teamJson))
	teamReq.Header.Set("Content-Type", "application/json")
	teamW := httptest.NewRecorder()
	handlers["POST /organization/team"](teamW, teamReq)

	if teamW.Code != http.StatusCreated {
		t.Fatalf("Create team failed: %s", teamW.Body.String())
	}

	var teamResp map[string]any
	json.Unmarshal(teamW.Body.Bytes(), &teamResp)
	teamID := teamResp["id"].(string)

	// 5. Add member to team (using service)
	_, err = service.AddTeamMember(ctx, teamID, member.ID)
	if err != nil {
		t.Fatalf("Add team member failed: %v", err)
	}

	// 6. Verify organization has 2 members
	members, err := service.ListMembers(ctx, orgID)
	if err != nil {
		t.Fatalf("List members failed: %v", err)
	}

	if len(members) != 2 {
		t.Errorf("len(members) = %d, want %d", len(members), 2)
	}

	// 7. Verify team has 1 member
	teamMembers, err := service.ListTeamMembers(ctx, teamID)
	if err != nil {
		t.Fatalf("List team members failed: %v", err)
	}

	if len(teamMembers) != 1 {
		t.Errorf("len(teamMembers) = %d, want %d", len(teamMembers), 1)
	}

	t.Log("Full organization workflow completed successfully")
}
