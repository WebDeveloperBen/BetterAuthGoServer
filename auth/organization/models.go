package organization

import (
	"time"

	"github.com/uptrace/bun"
)

// Organization represents an organization in the system
type Organization struct {
	bun.BaseModel `bun:"table:organizations,alias:o"`

	ID        string    `bun:"id,pk"`
	Name      string    `bun:"name,notnull"`
	Slug      string    `bun:"slug,notnull,unique"`
	Logo      *string   `bun:"logo"`
	Metadata  *string   `bun:"metadata"` // JSON string
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,default:current_timestamp"`
}

// Member represents a user's membership in an organization
type Member struct {
	bun.BaseModel `bun:"table:members,alias:m"`

	ID             string    `bun:"id,pk"`
	UserID         string    `bun:"user_id,notnull"`
	OrganizationID string    `bun:"organization_id,notnull"`
	Role           string    `bun:"role,notnull"` // owner, admin, member
	CreatedAt      time.Time `bun:"created_at,notnull,default:current_timestamp"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id"`
	User         *User         `bun:"rel:belongs-to,join:user_id=id"`
}

// Invitation represents an invitation to join an organization
type Invitation struct {
	bun.BaseModel `bun:"table:invitations,alias:i"`

	ID             string     `bun:"id,pk"`
	Email          string     `bun:"email,notnull"`
	OrganizationID string     `bun:"organization_id,notnull"`
	InviterID      string     `bun:"inviter_id,notnull"`
	Role           string     `bun:"role,notnull"`   // owner, admin, member
	Status         string     `bun:"status,notnull"` // pending, accepted, rejected, cancelled
	ExpiresAt      *time.Time `bun:"expires_at"`
	CreatedAt      time.Time  `bun:"created_at,notnull,default:current_timestamp"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id"`
	Inviter      *User         `bun:"rel:belongs-to,join:inviter_id=id"`
}

// Team represents a team within an organization
type Team struct {
	bun.BaseModel `bun:"table:teams,alias:t"`

	ID             string    `bun:"id,pk"`
	Name           string    `bun:"name,notnull"`
	OrganizationID string    `bun:"organization_id,notnull"`
	CreatedAt      time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt      time.Time `bun:"updated_at,nullzero,default:current_timestamp"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id"`
}

// TeamMember represents a user's membership in a team
type TeamMember struct {
	bun.BaseModel `bun:"table:team_members,alias:tm"`

	ID        string    `bun:"id,pk"`
	TeamID    string    `bun:"team_id,notnull"`
	UserID    string    `bun:"user_id,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`

	// Relations
	Team *Team `bun:"rel:belongs-to,join:team_id=id"`
	User *User `bun:"rel:belongs-to,join:user_id=id"`
}

// User is a minimal user representation for relations
// This avoids importing the full models package
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID    string `bun:"id,pk"`
	Email string `bun:"email"`
	Name  string `bun:"name"`
}

// SessionExtension extends the sessions table with organization context fields.
// This is added to the sessions table when the organization plugin is installed.
type SessionExtension struct {
	bun.BaseModel `bun:"table:sessions,alias:s"`

	ActiveOrganizationID *string `bun:"active_organization_id"`
	ActiveTeamID         *string `bun:"active_team_id"`
}
