# workflow-plugin-auth0

Auth0 identity and access management provider plugin for Workflow. It uses the
official `github.com/auth0/go-auth0` Management API SDK.

## Capabilities

- `auth0.provider` module for Auth0 Management API client credentials or static
  token authentication
- Auth provider descriptor step for admin catalog integration
- User create/read/list/update/delete steps
- Role create/list and user-role assignment steps
- Client/application create/read/list/update/delete steps
- Connection list and organization create/read/list steps

The descriptor advertises only capabilities backed by the plugin's concrete
management steps.

## Install

```sh
wfctl plugin install workflow-plugin-auth0
```

## License

MIT
