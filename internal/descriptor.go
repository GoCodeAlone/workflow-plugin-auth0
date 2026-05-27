package internal

import (
	"context"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authProviderDescribeStep struct {
	name   string
	config map[string]any
}

func newAuthProviderDescribeStep(name string, config map[string]any) (sdk.StepInstance, error) {
	return &authProviderDescribeStep{name: name, config: config}, nil
}

func (s *authProviderDescribeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	providerID := firstNonEmpty(mergeMaps(s.config, current), "provider_id", "providerId")
	if providerID == "" {
		providerID = "auth0"
	}
	domain := firstNonEmpty(mergeMaps(s.config, current), "domain")
	return &sdk.StepResult{Output: map[string]any{
		"providers": []map[string]any{auth0ProviderDescriptor(providerID, domain)},
	}}, nil
}

func auth0ProviderDescriptor(providerID, domain string) map[string]any {
	return map[string]any{
		"id":             providerID,
		"label":          "Auth0",
		"description":    "Auth0 identity, OAuth/OIDC application, RBAC role, connection, organization, and tenant administration.",
		"categories":     []string{"identity_management", "oauth2_oidc", "rbac", "enterprise_sso"},
		"implementation": "workflow-plugin-auth0",
		"version":        Version,
		"docs_url":       "https://github.com/GoCodeAlone/workflow-plugin-auth0",
		"support_level":  "management",
		"capabilities": []map[string]any{
			auth0Capability("auth0_identity_management", "Identity management", "identity_management", "Manage Auth0 users and database/passwordless connection identities.", []string{"create:users", "read:users", "update:users", "delete:users"}, auth0Fields(domain)),
			auth0Capability("auth0_rbac_roles", "RBAC roles", "rbac", "Manage Auth0 roles and assign roles to users.", []string{"create:roles", "read:roles", "update:roles", "delete:roles"}, auth0Fields(domain)),
			auth0Capability("auth0_applications", "Applications and OIDC clients", "oauth2_oidc", "Manage Auth0 applications/clients used for OAuth and OpenID Connect.", []string{"create:clients", "read:clients", "update:clients", "delete:clients"}, auth0Fields(domain)),
			auth0Capability("auth0_enterprise_sso", "Connections and organizations", "enterprise_sso", "List Auth0 connections and manage organizations used for enterprise SSO and B2B access.", []string{"read:connections", "create:organizations", "read:organizations", "update:organizations", "delete:organizations"}, auth0Fields(domain)),
		},
	}
}

func auth0Capability(key, label, category, description string, appScopes []string, fields []map[string]any) map[string]any {
	return map[string]any{
		"key":                key,
		"label":              label,
		"category":           category,
		"description":        description,
		"supported":          true,
		"app_scopes":         appScopes,
		"admin_read_scopes":  []string{"admin.auth.providers.read"},
		"admin_write_scopes": []string{"admin.auth.providers.write"},
		"config_fields":      fields,
	}
}

func auth0Fields(domain string) []map[string]any {
	return []map[string]any{
		auth0Field("auth0_domain", "Auth0 domain", "text", "Auth0 tenant domain, for example example.us.auth0.com.", "Use the tenant domain without a URL path.", false, true, optionIfSet(normalizeDomain(domain))),
		auth0Field("auth0_auth_mode", "Credential mode", "select", "How Workflow authenticates management API calls to Auth0.", "Prefer client credentials with least-privilege Management API scopes. Static tokens are intended for short-lived operational use.", false, true, []map[string]any{
			{"value": "client_credentials", "label": "Client credentials", "description": "Use an Auth0 M2M application client ID and client secret."},
			{"value": "static_token", "label": "Static token", "description": "Use a pre-issued Auth0 Management API bearer token."},
		}),
		auth0Field("auth0_client_id", "M2M client ID", "text", "Auth0 machine-to-machine application client ID.", "Required when credential mode is client credentials.", false, false, nil),
		auth0Field("auth0_client_secret", "M2M client secret", "secret", "Auth0 machine-to-machine application client secret.", "Write-only secret. Store through the application's secret provider.", true, false, nil),
		auth0Field("auth0_static_token", "Management API token", "secret", "Auth0 Management API bearer token.", "Write-only secret. Prefer client credentials for rotation and least privilege.", true, false, nil),
		auth0Field("auth0_management_scopes", "Management API scopes", "multiselect", "Auth0 Management API scopes required by enabled capabilities.", "Select the least-privilege scopes granted to the M2M application.", false, false, auth0ScopeOptions()),
	}
}

func auth0Field(key, label, inputType, description, helpText string, secret, required bool, options []map[string]any) map[string]any {
	return map[string]any{
		"key":         key,
		"label":       label,
		"input_type":  inputType,
		"description": description,
		"help_text":   helpText,
		"secret":      secret,
		"required":    required,
		"options":     options,
	}
}

func optionIfSet(value string) []map[string]any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return []map[string]any{{"value": value, "label": value}}
}

func auth0ScopeOptions() []map[string]any {
	scopes := []string{
		"create:users", "read:users", "update:users", "delete:users",
		"create:roles", "read:roles", "update:roles", "delete:roles",
		"create:clients", "read:clients", "update:clients", "delete:clients",
		"read:connections",
		"create:organizations", "read:organizations", "update:organizations", "delete:organizations",
	}
	options := make([]map[string]any, 0, len(scopes))
	for _, scope := range scopes {
		options = append(options, map[string]any{"value": scope, "label": scope})
	}
	return options
}
