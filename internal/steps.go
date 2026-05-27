package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	mgmt "github.com/auth0/go-auth0/management"
)

type stepConstructor func(name string, config map[string]any) (sdk.StepInstance, error)

var stepRegistry = map[string]stepConstructor{
	"step.auth0_auth_provider_describe": newAuthProviderDescribeStep,
	"step.auth0_user_create":            newManagementStep("users", auth0UserCreate),
	"step.auth0_user_get":               newManagementStep("users", auth0UserGet),
	"step.auth0_user_list":              newManagementStep("users", auth0UserList),
	"step.auth0_user_update":            newManagementStep("users", auth0UserUpdate),
	"step.auth0_user_delete":            newManagementStep("users", auth0UserDelete),
	"step.auth0_role_create":            newManagementStep("roles", auth0RoleCreate),
	"step.auth0_role_list":              newManagementStep("roles", auth0RoleList),
	"step.auth0_role_assign_users":      newManagementStep("roles", auth0RoleAssignUsers),
	"step.auth0_client_create":          newManagementStep("clients", auth0ClientCreate),
	"step.auth0_client_get":             newManagementStep("clients", auth0ClientGet),
	"step.auth0_client_list":            newManagementStep("clients", auth0ClientList),
	"step.auth0_client_update":          newManagementStep("clients", auth0ClientUpdate),
	"step.auth0_client_delete":          newManagementStep("clients", auth0ClientDelete),
	"step.auth0_connection_list":        newManagementStep("connections", auth0ConnectionList),
	"step.auth0_organization_create":    newManagementStep("organizations", auth0OrganizationCreate),
	"step.auth0_organization_get":       newManagementStep("organizations", auth0OrganizationGet),
	"step.auth0_organization_list":      newManagementStep("organizations", auth0OrganizationList),
}

func allStepTypes() []string {
	return []string{
		"step.auth0_auth_provider_describe",
		"step.auth0_user_create",
		"step.auth0_user_get",
		"step.auth0_user_list",
		"step.auth0_user_update",
		"step.auth0_user_delete",
		"step.auth0_role_create",
		"step.auth0_role_list",
		"step.auth0_role_assign_users",
		"step.auth0_client_create",
		"step.auth0_client_get",
		"step.auth0_client_list",
		"step.auth0_client_update",
		"step.auth0_client_delete",
		"step.auth0_connection_list",
		"step.auth0_organization_create",
		"step.auth0_organization_get",
		"step.auth0_organization_list",
	}
}

func createStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	constructor, ok := stepRegistry[typeName]
	if !ok {
		return nil, fmt.Errorf("auth0 plugin: unknown step type %q", typeName)
	}
	return constructor(name, config)
}

type managementHandler func(context.Context, *mgmt.Management, map[string]any) (map[string]any, error)

type managementStep struct {
	name       string
	moduleName string
	handler    managementHandler
}

func newManagementStep(_ string, handler managementHandler) stepConstructor {
	return func(name string, config map[string]any) (sdk.StepInstance, error) {
		moduleName := stringValue(config, "module")
		if moduleName == "" {
			moduleName = "auth0"
		}
		return &managementStep{name: name, moduleName: moduleName, handler: handler}, nil
	}
}

func (s *managementStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current, _, config map[string]any) (*sdk.StepResult, error) {
	client, ok := GetClient(s.moduleName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{"error": "auth0 client not found: " + s.moduleName}}, nil
	}
	output, err := s.handler(ctx, client.Management, mergeMaps(config, current))
	if err != nil {
		return &sdk.StepResult{Output: errResult(err)}, nil
	}
	return &sdk.StepResult{Output: output}, nil
}

func auth0UserCreate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	user := &mgmt.User{}
	if err := decodeMap(values, user); err != nil {
		return nil, err
	}
	if user.Connection == nil || *user.Connection == "" {
		return nil, fmt.Errorf("connection is required")
	}
	if user.Email == nil && user.PhoneNumber == nil && user.Username == nil {
		return nil, fmt.Errorf("email, phone_number, or username is required")
	}
	if err := client.User.Create(ctx, user); err != nil {
		return nil, err
	}
	return encodeValue(user)
}

func auth0UserGet(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "user_id", "userId", "id")
	if id == "" {
		return nil, fmt.Errorf("user_id is required")
	}
	user, err := client.User.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return encodeValue(user)
}

func auth0UserList(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	users, err := client.User.List(ctx, listOptions(values)...)
	if err != nil {
		return nil, err
	}
	return encodeList("users", users)
}

func auth0UserUpdate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "user_id", "userId", "id")
	if id == "" {
		return nil, fmt.Errorf("user_id is required")
	}
	user := &mgmt.User{}
	if payload := mapValue(values, "user"); payload != nil {
		if err := decodeMap(payload, user); err != nil {
			return nil, err
		}
	} else if err := decodeMap(values, user); err != nil {
		return nil, err
	}
	if err := client.User.Update(ctx, id, user); err != nil {
		return nil, err
	}
	return map[string]any{"updated": true, "user_id": id}, nil
}

func auth0UserDelete(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "user_id", "userId", "id")
	if id == "" {
		return nil, fmt.Errorf("user_id is required")
	}
	if err := client.User.Delete(ctx, id); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": true, "user_id": id}, nil
}

func auth0RoleCreate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	role := &mgmt.Role{}
	if err := decodeMap(values, role); err != nil {
		return nil, err
	}
	if role.Name == nil || *role.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := client.Role.Create(ctx, role); err != nil {
		return nil, err
	}
	return encodeValue(role)
}

func auth0RoleList(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	roles, err := client.Role.List(ctx, listOptions(values)...)
	if err != nil {
		return nil, err
	}
	return encodeList("roles", roles)
}

func auth0RoleAssignUsers(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	roleID := firstNonEmpty(values, "role_id", "roleId", "id")
	if roleID == "" {
		return nil, fmt.Errorf("role_id is required")
	}
	userIDs := stringSliceValue(values, "user_ids")
	if len(userIDs) == 0 {
		userIDs = stringSliceValue(values, "userIds")
	}
	if len(userIDs) == 0 {
		return nil, fmt.Errorf("user_ids is required")
	}
	users := make([]*mgmt.User, 0, len(userIDs))
	for _, id := range userIDs {
		userID := id
		users = append(users, &mgmt.User{ID: &userID})
	}
	if err := client.Role.AssignUsers(ctx, roleID, users); err != nil {
		return nil, err
	}
	return map[string]any{"assigned": true, "role_id": roleID, "user_ids": userIDs}, nil
}

func auth0ClientCreate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	auth0Client := &mgmt.Client{}
	if err := decodeMap(values, auth0Client); err != nil {
		return nil, err
	}
	if auth0Client.Name == nil || *auth0Client.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := client.Client.Create(ctx, auth0Client); err != nil {
		return nil, err
	}
	return encodeValue(auth0Client)
}

func auth0ClientGet(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "client_id", "clientId", "id")
	if id == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	auth0Client, err := client.Client.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return encodeValue(auth0Client)
}

func auth0ClientList(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	clients, err := client.Client.List(ctx, listOptions(values)...)
	if err != nil {
		return nil, err
	}
	return encodeList("clients", clients)
}

func auth0ClientUpdate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "client_id", "clientId", "id")
	if id == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	auth0Client := &mgmt.Client{}
	if payload := mapValue(values, "client"); payload != nil {
		if err := decodeMap(payload, auth0Client); err != nil {
			return nil, err
		}
	} else if err := decodeMap(values, auth0Client); err != nil {
		return nil, err
	}
	if err := client.Client.Update(ctx, id, auth0Client); err != nil {
		return nil, err
	}
	return map[string]any{"updated": true, "client_id": id}, nil
}

func auth0ClientDelete(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	id := firstNonEmpty(values, "client_id", "clientId", "id")
	if id == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if err := client.Client.Delete(ctx, id); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": true, "client_id": id}, nil
}

func auth0ConnectionList(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	connections, err := client.Connection.List(ctx, listOptions(values)...)
	if err != nil {
		return nil, err
	}
	return encodeList("connections", connections)
}

func auth0OrganizationCreate(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	org := &mgmt.Organization{}
	if err := decodeMap(values, org); err != nil {
		return nil, err
	}
	if org.Name == nil || *org.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := client.Organization.Create(ctx, org); err != nil {
		return nil, err
	}
	return encodeValue(org)
}

func auth0OrganizationGet(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	if name := stringValue(values, "name"); name != "" {
		org, err := client.Organization.ReadByName(ctx, name)
		if err != nil {
			return nil, err
		}
		return encodeValue(org)
	}
	id := firstNonEmpty(values, "organization_id", "organizationId", "id")
	if id == "" {
		return nil, fmt.Errorf("organization_id or name is required")
	}
	org, err := client.Organization.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return encodeValue(org)
}

func auth0OrganizationList(ctx context.Context, client *mgmt.Management, values map[string]any) (map[string]any, error) {
	orgs, err := client.Organization.List(ctx, listOptions(values)...)
	if err != nil {
		return nil, err
	}
	return encodeList("organizations", orgs)
}

func listOptions(values map[string]any) []mgmt.RequestOption {
	page := intValue(values, "page", 0)
	perPage := intValue(values, "per_page", 50)
	if perPage <= 0 || perPage > 100 {
		perPage = 50
	}
	options := []mgmt.RequestOption{mgmt.Page(page), mgmt.PerPage(perPage), mgmt.IncludeTotals(true)}
	if query := stringValue(values, "q"); query != "" {
		options = append(options, mgmt.Query(query))
	}
	return options
}

func firstNonEmpty(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(values, key); value != "" {
			return value
		}
	}
	return ""
}
