-- Organizations

-- name: CreateOrganization :exec
INSERT INTO organizations (id, name, slug, logo, metadata, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOrganizationByID :one
SELECT * FROM organizations WHERE id = $1;

-- name: GetOrganizationBySlug :one
SELECT * FROM organizations WHERE slug = $1;

-- name: UpdateOrganization :exec
UPDATE organizations
SET name = $2, slug = $3, logo = $4, metadata = $5, updated_at = $6
WHERE id = $1;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE id = $1;

-- name: ListUserOrganizations :many
SELECT o.* FROM organizations o
INNER JOIN members m ON o.id = m.organization_id
WHERE m.user_id = $1
ORDER BY o.created_at DESC;

-- name: CheckSlugExists :one
SELECT COUNT(*) > 0 as slug_exists FROM organizations WHERE slug = $1;

-- Members

-- name: CreateMember :exec
INSERT INTO members (id, organization_id, user_id, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetMember :one
SELECT * FROM members WHERE organization_id = $1 AND user_id = $2;

-- name: GetMemberByID :one
SELECT * FROM members WHERE id = $1;

-- name: ListMembersByOrganization :many
SELECT * FROM members WHERE organization_id = $1 ORDER BY created_at ASC;

-- name: ListMembersByUser :many
SELECT * FROM members WHERE user_id = $1 ORDER BY created_at ASC;

-- name: UpdateMemberRole :exec
UPDATE members SET role = $2, updated_at = $3 WHERE id = $1;

-- name: DeleteMember :exec
DELETE FROM members WHERE organization_id = $1 AND user_id = $2;

-- name: DeleteMemberByID :exec
DELETE FROM members WHERE id = $1;

-- name: CountOrganizationMembers :one
SELECT COUNT(*) FROM members WHERE organization_id = $1;

-- name: GetFirstMemberByUser :one
SELECT * FROM members WHERE user_id = $1 LIMIT 1;

-- Invitations

-- name: CreateInvitation :exec
INSERT INTO invitations (id, email, organization_id, inviter_id, role, status, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetInvitationByID :one
SELECT * FROM invitations WHERE id = $1;

-- name: GetInvitationByEmailAndOrg :one
SELECT * FROM invitations WHERE email = $1 AND organization_id = $2 AND status = 'pending';

-- name: ListInvitationsByOrganization :many
SELECT * FROM invitations WHERE organization_id = $1 ORDER BY created_at DESC;

-- name: ListInvitationsByEmail :many
SELECT * FROM invitations WHERE email = $1 AND status = 'pending' ORDER BY created_at DESC;

-- name: UpdateInvitationStatus :exec
UPDATE invitations SET status = $2 WHERE id = $1;

-- name: CancelPendingInvitations :exec
UPDATE invitations SET status = 'cancelled' WHERE email = $1 AND organization_id = $2 AND status = 'pending';

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE id = $1;

-- name: DeleteExpiredInvitations :execrows
DELETE FROM invitations WHERE status = 'pending' AND expires_at < NOW();

-- Teams

-- name: CreateTeam :exec
INSERT INTO teams (id, name, organization_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetTeamByID :one
SELECT * FROM teams WHERE id = $1;

-- name: ListTeamsByOrganization :many
SELECT * FROM teams WHERE organization_id = $1 ORDER BY created_at ASC;

-- name: UpdateTeam :exec
UPDATE teams SET name = $2, updated_at = $3 WHERE id = $1;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE id = $1;

-- Team Members

-- name: CreateTeamMember :exec
INSERT INTO team_members (id, team_id, user_id, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetTeamMember :one
SELECT * FROM team_members WHERE team_id = $1 AND user_id = $2;

-- name: ListTeamMembersByTeam :many
SELECT * FROM team_members WHERE team_id = $1 ORDER BY created_at ASC;

-- name: ListTeamMembersByUser :many
SELECT * FROM team_members WHERE user_id = $1 ORDER BY created_at ASC;

-- name: DeleteTeamMember :exec
DELETE FROM team_members WHERE team_id = $1 AND user_id = $2;

-- name: DeleteTeamMemberByID :exec
DELETE FROM team_members WHERE id = $1;

-- Note: Session active organization queries removed - columns must be added
-- to sessions table via runtime migration before these can be used.
