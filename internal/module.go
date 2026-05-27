package internal

import (
	"context"
	"fmt"
	"strings"

	mgmt "github.com/auth0/go-auth0/management"
)

type auth0Module struct {
	name   string
	config map[string]any
}

func newAuth0Module(name string, config map[string]any) (*auth0Module, error) {
	return &auth0Module{name: name, config: config}, nil
}

func (m *auth0Module) Init() error {
	domain := stringValue(m.config, "domain")
	if domain == "" {
		return fmt.Errorf("auth0.provider %q: domain is required", m.name)
	}
	domain = normalizeDomain(domain)

	clientID := stringValue(m.config, "clientId")
	if clientID == "" {
		clientID = stringValue(m.config, "client_id")
	}
	clientSecret := stringValue(m.config, "clientSecret")
	if clientSecret == "" {
		clientSecret = stringValue(m.config, "client_secret")
	}
	staticToken := stringValue(m.config, "staticToken")
	if staticToken == "" {
		staticToken = stringValue(m.config, "static_token")
	}

	var opts []mgmt.Option
	switch {
	case staticToken != "":
		opts = append(opts, mgmt.WithStaticToken(staticToken))
	case clientID != "" && clientSecret != "":
		opts = append(opts, mgmt.WithClientCredentials(context.Background(), clientID, clientSecret))
	default:
		return fmt.Errorf("auth0.provider %q: either staticToken or clientId+clientSecret are required", m.name)
	}

	client, err := mgmt.New(domain, opts...)
	if err != nil {
		return fmt.Errorf("auth0.provider %q: create management client: %w", m.name, err)
	}
	RegisterClient(m.name, &Auth0Client{Management: client, Domain: domain})
	return nil
}

func (m *auth0Module) Start(context.Context) error { return nil }

func (m *auth0Module) Stop(context.Context) error {
	UnregisterClient(m.name)
	return nil
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	return strings.TrimRight(domain, "/")
}
