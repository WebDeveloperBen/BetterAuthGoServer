// Package models contains shared types and interfaces for the auth package.
// This package has no internal dependencies and serves as the foundation for
// the auth system, providing type definitions used across all other packages.
package models

// ProviderType represents the type of authentication provider
type ProviderType string

const (
	ProviderEmail   ProviderType = "email"
	ProviderGoogle  ProviderType = "google"
	ProviderGitHub  ProviderType = "github"
	ProviderDiscord ProviderType = "discord"
)

// VerificationType represents the type of verification token
type VerificationType string

const (
	VerificationTypeEmail         VerificationType = "email_verification"
	VerificationTypePasswordReset VerificationType = "password_reset"
	VerificationTypeEmailChange   VerificationType = "email_change"
)
