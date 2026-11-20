package cli

// Add-on 3, update channel through Google (docs/optional-addons-plan.md
// §3, items G1, G2). NOT BUILT YET: lane L-google-pub fills in this file.
//
//	appsscript-script  --write-key-file           Code.gs and appsscript.json with the write key in them
//	appsscript-deploy  (access token on stdin)    Path A: create project, upload content, version,
//	                                              web-app deployment; prints the /exec URL
//	appsscript-check   --url --write-key-file     POST the current daal-refresh-v1 container, then
//	                                              fetch it back the way a recipient would
//	appsscript-clear   --url --write-key-file     POST an empty container (removal)
//
// Publishing an update is not a verb: it is one more backend inside
// publish-freshness (publisher/deploy/freshness/backends/appsscript).

import (
	"context"
	"io"
)

func runAppsScriptScript(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "appsscript-script")
}

func runAppsScriptDeploy(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_, _, _, _ = ctx, args, stdin, stdout
	return addonNotBuilt(stderr, "appsscript-deploy")
}

func runAppsScriptCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "appsscript-check")
}

func runAppsScriptClear(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "appsscript-clear")
}
