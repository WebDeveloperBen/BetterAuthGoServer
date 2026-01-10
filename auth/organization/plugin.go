package organization

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/access"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// PluginName is the identifier for the organization plugin.
const PluginName = "organization"

// Plugin provides organization and team management functionality.
type Plugin struct {
	ctx      plugin.Context
	logger   *slog.Logger
	service  *Service
	handlers *handlers
	config   Config
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
	_ plugin.MigrationsProvider = (*Plugin)(nil)
)

// NewPlugin creates a new organization plugin with options.
func NewPlugin(opts ...Option) *Plugin {
	config := DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}

	return &Plugin{
		config: config,
	}
}

// Name returns the plugin identifier.
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the organization plugin.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Use provided logger or default
	if ctx.Logger != nil {
		p.logger = ctx.Logger
	} else {
		p.logger = slog.Default()
	}

	if ctx.DB == nil {
		p.logger.Warn("organization plugin: no database available, plugin disabled")
		return nil
	}

	// Add session extension columns (these extend the existing sessions table)
	// Using ALTER TABLE since the sessions table is created by the core store
	if err := p.ensureSessionExtensionColumns(ctx.DB); err != nil {
		return fmt.Errorf("failed to add session extension columns: %w", err)
	}

	// Initialize access control
	if p.config.AccessControl == nil {
		ac, err := access.CreateDefaultAccessControl()
		if err != nil {
			return fmt.Errorf("failed to create default access control: %w", err)
		}
		p.config.AccessControl = ac
		if p.config.Roles == nil {
			owner, _ := ac.GetRole("owner")
			admin, _ := ac.GetRole("admin")
			member, _ := ac.GetRole("member")
			p.config.Roles = map[string]*access.Role{
				"owner":  owner,
				"admin":  admin,
				"member": member,
			}
		}
	}

	// Type-assert to get UserProvider for handlers
	userProvider, ok := ctx.Auth.(UserProvider)
	if !ok {
		p.logger.Warn("organization plugin: auth doesn't support UserProvider, plugin disabled")
		return nil
	}

	// Type-assert to get SessionInfoProvider for session management
	sessionInfoProvider, ok := ctx.Auth.(SessionInfoProvider)
	if !ok {
		p.logger.Warn("organization plugin: auth doesn't support SessionInfoProvider, session management disabled")
		return nil
	}

	// Create service
	p.service = NewService(ctx.DB, p.logger, &p.config)

	// Create handlers
	p.handlers = newHandlers(p.service, &p.config, userProvider, sessionInfoProvider)

	p.logger.Info("organization plugin initialized")
	return nil
}

// Close cleans up resources.
func (p *Plugin) Close() error {
	return nil
}

// Routes returns the organization API routes.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil {
		return nil
	}

	return []plugin.Route{
		// Organization CRUD
		{
			Method:      "POST",
			Path:        "/organization",
			Handler:     p.handlers.createOrganization,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization",
			Handler:     p.handlers.listUserOrganizations,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/check-slug",
			Handler:     p.handlers.checkSlug,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/full/",
			Handler:     p.handleFullOrganizationRoute,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/",
			Handler:     p.handleOrganizationRoutes,
			RequireAuth: true,
		},

		// Active organization
		{
			Method:      "GET",
			Path:        "/organization/active",
			Handler:     p.handlers.getActiveOrganization,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/organization/active",
			Handler:     p.handlers.setActiveOrganization,
			RequireAuth: true,
		},

		// Active member
		{
			Method:      "GET",
			Path:        "/organization/member/active",
			Handler:     p.handlers.getActiveMember,
			RequireAuth: true,
		},

		// Members
		{
			Method:      "POST",
			Path:        "/organization/member",
			Handler:     p.handleAddMember,
			RequireAuth: true,
		},

		// User invitations
		{
			Method:      "GET",
			Path:        "/organization/invitation/user",
			Handler:     p.handlers.listUserInvitations,
			RequireAuth: true,
		},

		// Invitations
		{
			Method:      "POST",
			Path:        "/organization/invitation",
			Handler:     p.handlers.createInvitation,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/invitation",
			Handler:     p.handlers.listInvitations,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/organization/invitation/",
			Handler:     p.handleInvitationRoutes,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/invitation/",
			Handler:     p.handleGetInvitationRoute,
			RequireAuth: true,
		},

		// Teams (if enabled)
		{
			Method:      "POST",
			Path:        "/organization/team",
			Handler:     p.handlers.createTeam,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/team",
			Handler:     p.handlers.listTeams,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/organization/team/",
			Handler:     p.handleTeamRoutes,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/organization/team/",
			Handler:     p.handleTeamMemberRoutes,
			RequireAuth: true,
		},
		{
			Method:      "DELETE",
			Path:        "/organization/team/",
			Handler:     p.handleTeamRoutes,
			RequireAuth: true,
		},
		{
			Method:      "PATCH",
			Path:        "/organization/team/",
			Handler:     p.handleTeamRoutes,
			RequireAuth: true,
		},
	}
}

// Middleware returns organization-related middleware.
func (p *Plugin) Middleware() []plugin.Middleware {
	return []plugin.Middleware{
		{
			Priority: 25, // Between auth (20-40) and other middleware
			Handler:  p.organizationContextMiddleware(),
		},
	}
}

// ensureSessionExtensionColumns adds organization-specific columns to the sessions table.
// This extends the core sessions table with active_organization_id and active_team_id.
// Checks if columns exist first to avoid SQL syntax errors.
func (p *Plugin) ensureSessionExtensionColumns(db *bun.DB) error {
	ctx := context.Background()

	// Check if columns already exist to avoid SQL syntax issues
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name IN ('active_organization_id', 'active_team_id')").Scan(&count); err != nil {
		return fmt.Errorf("failed to check existing columns: %w", err)
	}

	if count == 2 {
		// Both columns already exist
		return nil
	}

	// Add columns that don't exist
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'active_organization_id'").Scan(&count); err != nil {
		return fmt.Errorf("failed to check active_organization_id column: %w", err)
	}
	if count == 0 {
		if _, err := db.ExecContext(ctx, "ALTER TABLE sessions ADD COLUMN active_organization_id TEXT"); err != nil {
			return fmt.Errorf("failed to add active_organization_id column: %w", err)
		}
	}

	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'active_team_id'").Scan(&count); err != nil {
		return fmt.Errorf("failed to check active_team_id column: %w", err)
	}
	if count == 0 {
		if _, err := db.ExecContext(ctx, "ALTER TABLE sessions ADD COLUMN active_team_id TEXT"); err != nil {
			return fmt.Errorf("failed to add active_team_id column: %w", err)
		}
	}

	return nil
}

// Migrations returns database migrations for organization tables.
// Note: SessionExtension columns are added via ALTER TABLE in Init(),
// not here, because they extend an existing table rather than creating a new one.
func (p *Plugin) Migrations() []any {
	migrations := []any{
		(*Organization)(nil),
		(*Member)(nil),
		(*Invitation)(nil),
	}

	// Add team migrations if enabled
	if p.config.Teams.Enabled {
		migrations = append(migrations, (*Team)(nil), (*TeamMember)(nil))
	}

	return migrations
}

// handleOrganizationRoutes handles organization-specific routes.
func (p *Plugin) handleOrganizationRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/organization/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	orgIDOrSlug := parts[0]

	switch r.Method {
	case "GET":
		if len(parts) == 1 {
			p.handlers.getOrganization(w, r, orgIDOrSlug)
		} else if parts[1] == "members" {
			p.handlers.listMembers(w, r, orgIDOrSlug)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	case "PATCH":
		if len(parts) == 1 {
			p.handlers.updateOrganization(w, r, orgIDOrSlug)
		} else if len(parts) >= 3 && parts[1] == "members" {
			p.handlers.updateMemberRole(w, r, orgIDOrSlug)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "DELETE":
		if len(parts) == 1 {
			p.handlers.deleteOrganization(w, r, orgIDOrSlug)
		} else if len(parts) >= 3 && parts[1] == "members" {
			p.handlers.removeMember(w, r, orgIDOrSlug, parts[2])
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "POST":
		if len(parts) >= 2 && parts[1] == "leave" {
			p.handlers.leaveOrganization(w, r, orgIDOrSlug)
		} else if len(parts) >= 2 && parts[1] == "members" {
			p.handlers.addMember(w, r, orgIDOrSlug)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFullOrganizationRoute handles the full organization endpoint.
func (p *Plugin) handleFullOrganizationRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/organization/full/")
	if path == "" {
		http.Error(w, "organization id or slug required", http.StatusBadRequest)
		return
	}
	p.handlers.getFullOrganization(w, r, path)
}

// handleAddMember handles adding a member without organization in path.
func (p *Plugin) handleAddMember(w http.ResponseWriter, r *http.Request) {
	p.handlers.addMember(w, r, "")
}

// handleGetInvitationRoute handles GET /organization/invitation/{id}
func (p *Plugin) handleGetInvitationRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/organization/invitation/")
	if path == "" || path == "user" {
		http.Error(w, "invitation id required", http.StatusBadRequest)
		return
	}
	p.handlers.getInvitation(w, r, path)
}

// handleInvitationRoutes handles invitation-specific routes.
func (p *Plugin) handleInvitationRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/organization/invitation/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	invitationID := parts[0]

	switch r.Method {
	case "POST":
		if len(parts) == 1 {
			// Accept invitation
			p.handlers.acceptInvitation(w, r, invitationID)
		} else if parts[1] == "reject" {
			p.handlers.rejectInvitation(w, r, invitationID)
		} else if parts[1] == "cancel" {
			p.handlers.cancelInvitation(w, r, invitationID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "GET":
		if len(parts) == 1 {
			p.handlers.getInvitation(w, r, invitationID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTeamRoutes handles team-specific routes.
func (p *Plugin) handleTeamRoutes(w http.ResponseWriter, r *http.Request) {
	if !p.config.Teams.Enabled {
		http.Error(w, "teams not enabled", http.StatusNotFound)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/organization/team/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	teamID := parts[0]

	switch r.Method {
	case "GET":
		if len(parts) == 1 {
			p.handlers.getTeam(w, r, teamID)
		} else if parts[1] == "members" {
			p.handlers.listTeamMembers(w, r, teamID)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	case "PATCH":
		if len(parts) == 1 {
			p.handlers.updateTeam(w, r, teamID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "DELETE":
		if len(parts) == 1 {
			p.handlers.deleteTeam(w, r, teamID)
		} else if len(parts) >= 3 && parts[1] == "members" {
			p.handlers.removeTeamMember(w, r, teamID, parts[2])
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTeamMemberRoutes handles team member routes.
func (p *Plugin) handleTeamMemberRoutes(w http.ResponseWriter, r *http.Request) {
	if !p.config.Teams.Enabled {
		http.Error(w, "teams not enabled", http.StatusNotFound)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/organization/team/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 || parts[0] == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	teamID := parts[0]

	if parts[1] == "members" {
		p.handlers.addTeamMember(w, r, teamID)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// organizationContextMiddleware adds organization context to requests.
func (p *Plugin) organizationContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add organization context to request if needed
			// This could extract active organization from session
			next.ServeHTTP(w, r)
		})
	}
}
