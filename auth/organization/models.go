package organization

import (
	"time"
)

// Organization represents an organization in the system
type Organization struct {
	ID        string
	Name      string
	Slug      string
	Logo      *string
	Metadata  *string // JSON string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Member represents a user's membership in an organization
type Member struct {
	ID             string
	UserID         string
	OrganizationID string
	Role           string // owner, admin, member
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Relations (loaded separately when needed)
	Organization *Organization
	User         *User
}

// Invitation represents an invitation to join an organization
type Invitation struct {
	ID             string
	Email          string
	OrganizationID string
	InviterID      string
	Role           string // owner, admin, member
	Status         string // pending, accepted, rejected, cancelled
	ExpiresAt      *time.Time
	CreatedAt      time.Time

	// Relations (loaded separately when needed)
	Organization *Organization
	Inviter      *User
}

// Team represents a team within an organization
type Team struct {
	ID             string
	Name           string
	OrganizationID string
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Relations (loaded separately when needed)
	Organization *Organization
}

// TeamMember represents a user's membership in a team
type TeamMember struct {
	ID        string
	TeamID    string
	UserID    string
	CreatedAt time.Time

	// Relations (loaded separately when needed)
	Team *Team
	User *User
}

// User is a minimal user representation for relations
// This avoids importing the full models package
type User struct {
	ID    string
	Email string
	Name  string
}

// SessionExtension extends the sessions table with organization context fields.
// This is added to the sessions table when the organization plugin is installed.
type SessionExtension struct {
	ActiveOrganizationID *string
	ActiveTeamID         *string
}
