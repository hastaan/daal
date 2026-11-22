// `daal-deploy users-share-links`: "Links for other apps".
//
// Renders the standard share links (vless:// REALITY, ss:// 2022, and the
// Cloudflare way when its commitment allows a plain hello; Hysteria 2 is
// left out until a pinned link is shown to work) for ONE person, from the same inputs as
// users-pack-sbp[x]: the signed .sbp, that person's creds JSON, the
// relay's address and cover host. See relaypack/share_links.go for the
// rule that decides which ways get a link.
//
// Secrets never ride argv: the creds arrive by --creds-file, or on stdin
// with --creds-file -. The links are printed on STDOUT only, as JSON:
//
//	{"links":[{"way","label","link"}], "left_out":[{"way","reason","detail"}]}
//
// Nothing about a link ever goes to stderr.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"daal/publisher/deploy/relaypack"
)

func runUsersShareLinks(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("users-share-links", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inPath := fs.String("in", "", "input .sbp path (Step 6 / bind-and-sign output)")
	credsFile := fs.String("creds-file", "", "this person's creds JSON (mgmt /users/provision shape); '-' reads it from stdin")
	server := fs.String("server", "", "box public IP/host the links dial")
	coverSNI := fs.String("cover-sni", "", "OperatorRecord.cover_sni for this relay; used only when the creds carry none")
	label := fs.String("label", "", "optional name put before each way's name in the link labels (e.g. the relay's name)")
	cdnFlags := addCDNPackFlags(fs)
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{
		"--in":         *inPath,
		"--creds-file": *credsFile,
		"--server":     *server,
	}); err != nil {
		return 2
	}

	sbp, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}

	path := *credsFile
	if path == "-" {
		// Read straight from the inherited stdin: no temp copy of the
		// creds ever lands on disk.
		if stdin != os.Stdin {
			fmt.Fprintln(stderr, "--creds-file -: stdin is not the process's stdin")
			return 2
		}
		path = "/dev/stdin"
	}
	params, err := clientParamsFromCredsFile(path, *server, *coverSNI)
	if err != nil {
		fmt.Fprintf(stderr, "creds-file: %v\n", err)
		return 2
	}
	if err := cdnFlags.apply(&params); err != nil {
		fmt.Fprintf(stderr, "users-share-links: %v\n", err)
		return 2
	}

	links, left, err := relaypack.ShareLinksForRecipient(sbp, params, *label)
	if err != nil {
		// relaypack never puts a credential or a link in an error.
		fmt.Fprintf(stderr, "share links: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(map[string]any{
		"links":    links,
		"left_out": left,
	}); err != nil {
		fmt.Fprintf(stderr, "encode: %v\n", err)
		return 1
	}
	return 0
}
