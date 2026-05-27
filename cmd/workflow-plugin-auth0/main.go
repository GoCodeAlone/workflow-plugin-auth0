package main

import (
	"github.com/GoCodeAlone/workflow-plugin-auth0/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewAuth0Plugin(), sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)))
}
