package cli

// Optional add-ons (docs/optional-addons-plan.md, X2;
// specs/optional-addons-v1.md §6): what the add-on verbs share.
//
// Every add-on verb is registered once in Run (cli.go) and lives in its
// own file, which its lane fills in:
//
//	cli_addon_standby.go  standby price | add | promote | remove   (L-standby-pub, S5)
//	cli_addon_cdn.go      cdn-token-check, cdn-test, cdn-posture,
//	                      cdn-remove                                (L-cdn-server, B-3)
//	cli_addon_google.go   appsscript-script, appsscript-deploy,
//	                      appsscript-check, appsscript-clear        (L-google-pub, G1/G2)
//
// Until then each one refuses with exitNotBuilt and a line that starts
// with "E_NOT_BUILT:". That is not "unknown subcommand" (exit 2) on
// purpose: the app reads exit 2 as "this helper is older than the app".

import (
	"fmt"
	"io"
)

// exitNotBuilt is the exit code of an add-on verb whose code has not
// landed. Nothing was read, created or changed.
const exitNotBuilt = 8

// addonNotBuilt writes the refusal and returns exitNotBuilt.
func addonNotBuilt(stderr io.Writer, verb string) int {
	fmt.Fprintf(stderr, "E_NOT_BUILT: daal-deploy %s is not built yet\n", verb)
	return exitNotBuilt
}
