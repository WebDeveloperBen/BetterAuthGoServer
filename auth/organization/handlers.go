package organization

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// handlers holds the organization handlers with access to the service
type handlers struct {
	service     *Service
	config      *Config
	auth        UserProvider
	sessionInfo SessionInfoProvider
}

func newHandlers(service *Service, config *Config, auth UserProvider, sessionInfo SessionInfoProvider) *handlers {
	return &handlers{
		service:     service,
		config:      config,
		auth:        auth,
		sessionInfo: sessionInfo,
	}
}

// Request types

type createOrganizationRequest struct {
	Name     string         `json:"name"`
	Slug     string         `json:"slug"`
	Logo     *string        `json:"logo,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type updateOrganizationRequest struct {
	Name     *string        `json:"name,omitempty"`
	Slug     *string        `json:"slug,omitempty"`
	Logo     *string        `json:"logo,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type createInvitationRequest struct {
	Email          string  `json:"email"`
	Role           string  `json:"role"`
	OrganizationID *string `json:"organizationId,omitempty"`
	Resend         bool    `json:"resend,omitempty"`
}

type addMemberRequest struct {
	UserID         string  `json:"userId"`
	Role           string  `json:"role"`
	OrganizationID *string `json:"organizationId,omitempty"`
}

type updateMemberRoleRequest struct {
	Role     string `json:"role"`
	MemberID string `json:"memberId"`
}

type setActiveOrganizationRequest struct {
	OrganizationID   *string `json:"organizationId,omitempty"`
	OrganizationSlug *string `json:"organizationSlug,omitempty"`
}

type createTeamRequest struct {
	Name           string  `json:"name"`
	OrganizationID *string `json:"organizationId,omitempty"`
}

type updateTeamRequest struct {
	Name string `json:"name"`
}

type teamMemberRequest struct {
	UserID string `json:"userId"`
}

// Response types

type organizationResponse struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	Logo      *string        `json:"logo,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt string         `json:"updatedAt"`
}

type memberResponse struct {
	ID             string        `json:"id"`
	UserID         string        `json:"userId"`
	OrganizationID string        `json:"organizationId"`
	Role           string        `json:"role"`
	CreatedAt      string        `json:"createdAt"`
	User           *userResponse `json:"user,omitempty"`
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type invitationResponse struct {
	ID             string  `json:"id"`
	Email          string  `json:"email"`
	OrganizationID string  `json:"organizationId"`
	InviterID      string  `json:"inviterId"`
	Role           string  `json:"role"`
	Status         string  `json:"status"`
	ExpiresAt      *string `json:"expiresAt,omitempty"`
	CreatedAt      string  `json:"createdAt"`
}

type teamResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organizationId"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

type teamMemberResponse struct {
	ID        string `json:"id"`
	TeamID    string `json:"teamId"`
	UserID    string `json:"userId"`
	CreatedAt string `json:"createdAt"`
}

type fullOrganizationResponse struct {
	Organization *organizationResponse `json:"organization"`
	Members      []*memberResponse     `json:"members"`
	Invitations  []*invitationResponse `json:"invitations,omitempty"`
	Teams        []*teamResponse       `json:"teams,omitempty"`
}

type listOrganizationsResponse struct {
	Organizations []*organizationResponse `json:"organizations"`
}

type listMembersResponse struct {
	Members []*memberResponse `json:"members"`
	Total   int               `json:"total"`
}

type listInvitationsResponse struct {
	Invitations []*invitationResponse `json:"invitations"`
}

type listTeamsResponse struct {
	Teams []*teamResponse `json:"teams"`
}

type listTeamMembersResponse struct {
	Members []*teamMemberResponse `json:"members"`
}

type slugCheckResponse struct {
	Available bool `json:"available"`
}

// Conversion helpers

func toOrganizationResponse(org *Organization) *organizationResponse {
	if org == nil {
		return nil
	}

	resp := &organizationResponse{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      org.Logo,
		CreatedAt: org.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: org.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	// Parse metadata if present
	if org.Metadata != nil {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(*org.Metadata), &metadata); err == nil {
			resp.Metadata = metadata
		}
	}

	return resp
}

func toMemberResponse(m *Member) *memberResponse {
	if m == nil {
		return nil
	}

	resp := &memberResponse{
		ID:             m.ID,
		UserID:         m.UserID,
		OrganizationID: m.OrganizationID,
		Role:           m.Role,
		CreatedAt:      m.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if m.User != nil {
		resp.User = &userResponse{
			ID:    m.User.ID,
			Email: m.User.Email,
			Name:  m.User.Name,
		}
	}

	return resp
}

func toInvitationResponse(inv *Invitation) *invitationResponse {
	if inv == nil {
		return nil
	}

	resp := &invitationResponse{
		ID:             inv.ID,
		Email:          inv.Email,
		OrganizationID: inv.OrganizationID,
		InviterID:      inv.InviterID,
		Role:           inv.Role,
		Status:         inv.Status,
		CreatedAt:      inv.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if inv.ExpiresAt != nil {
		exp := inv.ExpiresAt.Format("2006-01-02T15:04:05Z")
		resp.ExpiresAt = &exp
	}

	return resp
}

func toTeamResponse(t *Team) *teamResponse {
	if t == nil {
		return nil
	}

	return &teamResponse{
		ID:             t.ID,
		Name:           t.Name,
		OrganizationID: t.OrganizationID,
		CreatedAt:      t.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      t.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func toTeamMemberResponse(tm *TeamMember) *teamMemberResponse {
	if tm == nil {
		return nil
	}

	return &teamMemberResponse{
		ID:        tm.ID,
		TeamID:    tm.TeamID,
		UserID:    tm.UserID,
		CreatedAt: tm.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// Organization CRUD handlers

func (h *handlers) createOrganization(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	var req createOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	if req.Slug == "" {
		writeError(w, http.StatusBadRequest, errors.New("slug is required"))
		return
	}

	org, err := h.service.CreateOrganization(r.Context(), req.Name, req.Slug, user.ID, req.Metadata)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// Update logo if provided
	if req.Logo != nil {
		org, err = h.service.UpdateOrganization(r.Context(), org.ID, map[string]any{
			"logo": req.Logo,
		})
		if err != nil {
			// Log but don't fail - org was created
			h.service.logger.Error("failed to set logo", "error", err)
		}
	}

	writeJSON(w, http.StatusCreated, toOrganizationResponse(org))
}

func (h *handlers) listUserOrganizations(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	orgs, err := h.service.ListUserOrganizations(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list organizations"))
		return
	}

	resp := make([]*organizationResponse, len(orgs))
	for i, org := range orgs {
		resp[i] = toOrganizationResponse(org)
	}

	writeJSON(w, http.StatusOK, listOrganizationsResponse{Organizations: resp})
}

func (h *handlers) getOrganization(w http.ResponseWriter, r *http.Request, idOrSlug string) {
	// Try by ID first, then by slug
	org, err := h.service.GetOrganization(r.Context(), idOrSlug)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), idOrSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	writeJSON(w, http.StatusOK, toOrganizationResponse(org))
}

func (h *handlers) getFullOrganization(w http.ResponseWriter, r *http.Request, idOrSlug string) {
	// Get organization
	org, err := h.service.GetOrganization(r.Context(), idOrSlug)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), idOrSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	// Get members
	members, err := h.service.ListMembers(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list members"))
		return
	}

	memberResp := make([]*memberResponse, len(members))
	for i, m := range members {
		memberResp[i] = toMemberResponse(m)
	}

	resp := &fullOrganizationResponse{
		Organization: toOrganizationResponse(org),
		Members:      memberResp,
	}

	// Get invitations
	invitations, err := h.service.ListInvitations(r.Context(), org.ID)
	if err == nil {
		invResp := make([]*invitationResponse, len(invitations))
		for i, inv := range invitations {
			invResp[i] = toInvitationResponse(inv)
		}
		resp.Invitations = invResp
	}

	// Get teams if enabled
	if h.config.Teams.Enabled {
		teams, err := h.service.ListTeams(r.Context(), org.ID)
		if err == nil {
			teamResp := make([]*teamResponse, len(teams))
			for i, t := range teams {
				teamResp[i] = toTeamResponse(t)
			}
			resp.Teams = teamResp
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *handlers) updateOrganization(w http.ResponseWriter, r *http.Request, idOrSlug string) {
	var req updateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	// Find organization
	org, err := h.service.GetOrganization(r.Context(), idOrSlug)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), idOrSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	// Build updates map
	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Slug != nil {
		updates["slug"] = *req.Slug
	}
	if req.Logo != nil {
		updates["logo"] = req.Logo
	}
	if req.Metadata != nil {
		updates["metadata"] = req.Metadata
	}

	if len(updates) == 0 {
		writeJSON(w, http.StatusOK, toOrganizationResponse(org))
		return
	}

	updated, err := h.service.UpdateOrganization(r.Context(), org.ID, updates)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, toOrganizationResponse(updated))
}

func (h *handlers) deleteOrganization(w http.ResponseWriter, r *http.Request, idOrSlug string) {
	// Find organization
	org, err := h.service.GetOrganization(r.Context(), idOrSlug)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), idOrSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	if err := h.service.DeleteOrganization(r.Context(), org.ID); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to delete organization"))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) checkSlug(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, errors.New("slug is required"))
		return
	}

	_, err := h.service.GetOrganizationBySlug(r.Context(), slug)
	available := err != nil // If error (not found), slug is available

	writeJSON(w, http.StatusOK, slugCheckResponse{Available: available})
}

// Member management handlers

func (h *handlers) listMembers(w http.ResponseWriter, r *http.Request, organizationID string) {
	// Parse pagination parameters
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))

	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	// Find organization first
	org, err := h.service.GetOrganization(r.Context(), organizationID)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), organizationID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	members, err := h.service.ListMembers(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list members"))
		return
	}

	// Apply pagination
	total := len(members)
	if offset >= len(members) {
		members = []*Member{}
	} else {
		end := min(offset+limit, len(members))
		members = members[offset:end]
	}

	resp := make([]*memberResponse, len(members))
	for i, m := range members {
		resp[i] = toMemberResponse(m)
	}

	writeJSON(w, http.StatusOK, listMembersResponse{Members: resp, Total: total})
}

func (h *handlers) addMember(w http.ResponseWriter, r *http.Request, organizationID string) {
	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, errors.New("userId is required"))
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	// Use provided organizationID or from request body
	orgID := organizationID
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		orgID = *req.OrganizationID
	}

	member, err := h.service.AddMember(r.Context(), orgID, req.UserID, req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusCreated, toMemberResponse(member))
}

func (h *handlers) removeMember(w http.ResponseWriter, r *http.Request, organizationID, memberIDOrEmail string) {
	// Find organization
	org, err := h.service.GetOrganization(r.Context(), organizationID)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), organizationID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	// memberIDOrEmail could be a user ID or email - for now treat as user ID
	if err := h.service.RemoveMember(r.Context(), org.ID, memberIDOrEmail); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) updateMemberRole(w http.ResponseWriter, r *http.Request, organizationID string) {
	var req updateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.Role == "" {
		writeError(w, http.StatusBadRequest, errors.New("role is required"))
		return
	}
	if req.MemberID == "" {
		writeError(w, http.StatusBadRequest, errors.New("memberId is required"))
		return
	}

	// Find organization
	org, err := h.service.GetOrganization(r.Context(), organizationID)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), organizationID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	member, err := h.service.UpdateMemberRole(r.Context(), org.ID, req.MemberID, req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, toMemberResponse(member))
}

func (h *handlers) getActiveMember(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	member, err := h.service.GetActiveMember(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("no active membership"))
		return
	}

	writeJSON(w, http.StatusOK, toMemberResponse(member))
}

func (h *handlers) leaveOrganization(w http.ResponseWriter, r *http.Request, organizationID string) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	// Find organization
	org, err := h.service.GetOrganization(r.Context(), organizationID)
	if err != nil {
		org, err = h.service.GetOrganizationBySlug(r.Context(), organizationID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
	}

	if err := h.service.RemoveMember(r.Context(), org.ID, user.ID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Invitation handlers

func (h *handlers) createInvitation(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	var req createInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, errors.New("email is required"))
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	// Get organization ID - from request body or user's active org
	var orgID string
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		orgID = *req.OrganizationID
	} else {
		// Try to get from active membership
		member, err := h.service.GetActiveMember(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("organizationId is required"))
			return
		}
		orgID = member.OrganizationID
	}

	invitation, err := h.service.CreateInvitation(r.Context(), orgID, req.Email, req.Role, user.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusCreated, toInvitationResponse(invitation))
}

func (h *handlers) listInvitations(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	// Check if organizationId is provided
	orgID := r.URL.Query().Get("organizationId")
	if orgID == "" {
		// Get from active membership
		member, err := h.service.GetActiveMember(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("organizationId is required"))
			return
		}
		orgID = member.OrganizationID
	}

	invitations, err := h.service.ListInvitations(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list invitations"))
		return
	}

	resp := make([]*invitationResponse, len(invitations))
	for i, inv := range invitations {
		resp[i] = toInvitationResponse(inv)
	}

	writeJSON(w, http.StatusOK, listInvitationsResponse{Invitations: resp})
}

func (h *handlers) listUserInvitations(w http.ResponseWriter, r *http.Request) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	invitations, err := h.service.ListUserInvitations(r.Context(), user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list invitations"))
		return
	}

	resp := make([]*invitationResponse, len(invitations))
	for i, inv := range invitations {
		resp[i] = toInvitationResponse(inv)
	}

	writeJSON(w, http.StatusOK, listInvitationsResponse{Invitations: resp})
}

func (h *handlers) getInvitation(w http.ResponseWriter, r *http.Request, invitationID string) {
	invitation, err := h.service.GetInvitation(r.Context(), invitationID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("invitation not found"))
		return
	}

	writeJSON(w, http.StatusOK, toInvitationResponse(invitation))
}

func (h *handlers) acceptInvitation(w http.ResponseWriter, r *http.Request, invitationID string) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	member, err := h.service.AcceptInvitation(r.Context(), invitationID, user.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, toMemberResponse(member))
}

func (h *handlers) rejectInvitation(w http.ResponseWriter, r *http.Request, invitationID string) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	if err := h.service.RejectInvitation(r.Context(), invitationID, user.ID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) cancelInvitation(w http.ResponseWriter, r *http.Request, invitationID string) {
	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	if err := h.service.CancelInvitation(r.Context(), invitationID, user.ID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Team handlers

func (h *handlers) createTeam(w http.ResponseWriter, r *http.Request) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	var req createTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}

	// Get organization ID
	var orgID string
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		orgID = *req.OrganizationID
	} else {
		member, err := h.service.GetActiveMember(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("organizationId is required"))
			return
		}
		orgID = member.OrganizationID
	}

	team, err := h.service.CreateTeam(r.Context(), orgID, req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusCreated, toTeamResponse(team))
}

func (h *handlers) listTeams(w http.ResponseWriter, r *http.Request) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	user, err := h.auth.GetUserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	orgID := r.URL.Query().Get("organizationId")
	if orgID == "" {
		member, err := h.service.GetActiveMember(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("organizationId is required"))
			return
		}
		orgID = member.OrganizationID
	}

	teams, err := h.service.ListTeams(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list teams"))
		return
	}

	resp := make([]*teamResponse, len(teams))
	for i, t := range teams {
		resp[i] = toTeamResponse(t)
	}

	writeJSON(w, http.StatusOK, listTeamsResponse{Teams: resp})
}

func (h *handlers) getTeam(w http.ResponseWriter, r *http.Request, teamID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	team, err := h.service.GetTeam(r.Context(), teamID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("team not found"))
		return
	}

	writeJSON(w, http.StatusOK, toTeamResponse(team))
}

func (h *handlers) updateTeam(w http.ResponseWriter, r *http.Request, teamID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	var req updateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}

	team, err := h.service.UpdateTeam(r.Context(), teamID, req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, toTeamResponse(team))
}

func (h *handlers) deleteTeam(w http.ResponseWriter, r *http.Request, teamID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	if err := h.service.DeleteTeam(r.Context(), teamID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listTeamMembers(w http.ResponseWriter, r *http.Request, teamID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	members, err := h.service.ListTeamMembers(r.Context(), teamID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list team members"))
		return
	}

	resp := make([]*teamMemberResponse, len(members))
	for i, m := range members {
		resp[i] = toTeamMemberResponse(m)
	}

	writeJSON(w, http.StatusOK, listTeamMembersResponse{Members: resp})
}

func (h *handlers) addTeamMember(w http.ResponseWriter, r *http.Request, teamID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	var req teamMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, errors.New("userId is required"))
		return
	}

	member, err := h.service.AddTeamMember(r.Context(), teamID, req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusCreated, toTeamMemberResponse(member))
}

func (h *handlers) removeTeamMember(w http.ResponseWriter, r *http.Request, teamID, userID string) {
	if !h.config.Teams.Enabled {
		writeError(w, http.StatusNotFound, errors.New("teams are not enabled"))
		return
	}

	if err := h.service.RemoveTeamMember(r.Context(), teamID, userID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Active organization handlers

func (h *handlers) getActiveOrganization(w http.ResponseWriter, r *http.Request) {
	// Get session info from request
	sessionInfo := h.sessionInfo.GetSessionInfoFromRequest(r)
	if sessionInfo == nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	// Get active organization ID from session
	activeOrgID, err := h.service.GetActiveOrganization(r.Context(), sessionInfo.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to get active organization"))
		return
	}

	if activeOrgID == nil || *activeOrgID == "" {
		writeError(w, http.StatusNotFound, errors.New("no active organization"))
		return
	}

	org, err := h.service.GetOrganization(r.Context(), *activeOrgID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("organization not found"))
		return
	}

	writeJSON(w, http.StatusOK, toOrganizationResponse(org))
}

func (h *handlers) setActiveOrganization(w http.ResponseWriter, r *http.Request) {
	// Get session info from request
	sessionInfo := h.sessionInfo.GetSessionInfoFromRequest(r)
	if sessionInfo == nil {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	var req setActiveOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	// Resolve organization ID from slug if needed
	var orgID *string
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		orgID = req.OrganizationID
	} else if req.OrganizationSlug != nil && *req.OrganizationSlug != "" {
		// Look up by slug
		org, err := h.service.GetOrganizationBySlug(r.Context(), *req.OrganizationSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
		orgID = &org.ID
	}
	// If both are nil/empty, orgID stays nil (clearing active org)

	// Verify user is a member of this organization (if setting one)
	if orgID != nil && *orgID != "" {
		_, err := h.service.GetMember(r.Context(), *orgID, sessionInfo.UserID)
		if err != nil {
			writeError(w, http.StatusForbidden, errors.New("not a member of this organization"))
			return
		}
	}

	// Set the active organization on the session
	if err := h.service.SetActiveOrganization(r.Context(), sessionInfo.ID, orgID); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to set active organization"))
		return
	}

	// Return the organization if one was set
	if orgID != nil && *orgID != "" {
		org, err := h.service.GetOrganization(r.Context(), *orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("failed to get organization"))
			return
		}
		writeJSON(w, http.StatusOK, toOrganizationResponse(org))
		return
	}

	// Returning null when clearing active org
	writeJSON(w, http.StatusOK, nil)
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{
		"error":   http.StatusText(status),
		"message": err.Error(),
	})
}
