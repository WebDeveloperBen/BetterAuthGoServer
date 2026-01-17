-- Organizations

-- name: CreateOrganization :exec
INSERT INTO organizations (id, name, slug, logo, metadata, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOrganizationByID :one
SELECT * FROM organizations WHERE id = ?;

-- name: GetOrganizationBySlug :one
SELECT * FROM organizations WHERE slug = ?;

-- name: UpdateOrganization :exec
UPDATE organizations
SET name = ?, slug = ?, logo = ?, metadata = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE id = ?;

-- name: ListUserOrganizations :many
SELECT o.* FROM organizations o
INNER JOIN members m ON o.id = m.organization_id
WHERE m.user_id = ?
ORDER BY o.created_at DESC;

-- name: CheckSlugExists :one
SELECT COUNT(*) > 0 as slug_exists FROM organizations WHERE slug = ?;

-- Members

-- name: CreateMember :exec
INSERT INTO members (id, organization_id, user_id, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMember :one
SELECT * FROM members WHERE organization_id = ? AND user_id = ?;

-- name: GetMemberByID :one
SELECT * FROM members WHERE id = ?;

-- name: ListMembersByOrganization :many
SELECT * FROM members WHERE organization_id = ? ORDER BY created_at ASC;

-- name: ListMembersByUser :many
SELECT * FROM members WHERE user_id = ? ORDER BY created_at ASC;

-- name: UpdateMemberRole :exec
UPDATE members SET role = ?, updated_at = ? WHERE id = ?;

-- name: DeleteMember :exec
DELETE FROM members WHERE organization_id = ? AND user_id = ?;

-- name: DeleteMemberByID :exec
DELETE FROM members WHERE id = ?;

-- name: CountOrganizationMembers :one
SELECT COUNT(*) FROM members WHERE organization_id = ?;

-- name: GetFirstMemberByUser :one
SELECT * FROM members WHERE user_id = ? LIMIT 1;

-- Invitations

-- name: CreateInvitation :exec
INSERT INTO invitations (id, email, organization_id, inviter_id, role, status, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInvitationByID :one
SELECT * FROM invitations WHERE id = ?;

-- name: GetInvitationByEmailAndOrg :one
SELECT * FROM invitations WHERE email = ? AND organization_id = ? AND status = 'pending';

-- name: ListInvitationsByOrganization :many
SELECT * FROM invitations WHERE organization_id = ? ORDER BY created_at DESC;

-- name: ListInvitationsByEmail :many
SELECT * FROM invitations WHERE email = ? AND status = 'pending' ORDER BY created_at DESC;

-- name: UpdateInvitationStatus :exec
UPDATE invitations SET status = ? WHERE id = ?;

-- name: CancelPendingInvitations :exec
UPDATE invitations SET status = 'cancelled' WHERE email = ? AND organization_id = ? AND status = 'pending';

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE id = ?;

-- name: DeleteExpiredInvitations :execrows
DELETE FROM invitations WHERE status = 'pending' AND expires_at < NOW(6);

-- Teams

-- name: CreateTeam :exec
INSERT INTO teams (id, name, organization_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetTeamByID :one
SELECT * FROM teams WHERE id = ?;

-- name: ListTeamsByOrganization :many
SELECT * FROM teams WHERE organization_id = ? ORDER BY created_at ASC;

-- name: UpdateTeam :exec
UPDATE teams SET name = ?, updated_at = ? WHERE id = ?;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE id = ?;

-- Team Members

-- name: CreateTeamMember :exec
INSERT INTO team_members (id, team_id, user_id, created_at)
VALUES (?, ?, ?, ?);

-- name: GetTeamMember :one
SELECT * FROM team_members WHERE team_id = ? AND user_id = ?;

-- name: ListTeamMembersByTeam :many
SELECT * FROM team_members WHERE team_id = ? ORDER BY created_at ASC;

-- name: ListTeamMembersByUser :many
SELECT * FROM team_members WHERE user_id = ? ORDER BY created_at ASC;

-- name: DeleteTeamMember :exec
DELETE FROM team_members WHERE team_id = ? AND user_id = ?;

-- name: DeleteTeamMemberByID :exec
DELETE FROM team_members WHERE id = ?;

-- Note: Session active organization queries removed - columns must be added
-- to sessions table via runtime migration before these can be used.
