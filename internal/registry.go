package internal

import (
	"sync"

	mgmt "github.com/auth0/go-auth0/management"
)

type Auth0Client struct {
	Management *mgmt.Management
	Domain     string
}

var (
	clientMu       sync.RWMutex
	clientRegistry = map[string]*Auth0Client{}
)

func RegisterClient(name string, client *Auth0Client) {
	clientMu.Lock()
	defer clientMu.Unlock()
	clientRegistry[name] = client
}

func GetClient(name string) (*Auth0Client, bool) {
	clientMu.RLock()
	defer clientMu.RUnlock()
	client, ok := clientRegistry[name]
	return client, ok
}

func UnregisterClient(name string) {
	clientMu.Lock()
	defer clientMu.Unlock()
	delete(clientRegistry, name)
}
