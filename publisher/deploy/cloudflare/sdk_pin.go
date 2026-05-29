//go:build tools

package cloudflare

// Keep Cloudflare's generated v4 SDK pinned in publisher/go.mod as
// the phase-level dependency lock, even though FRP-8's critical path
// uses Daal's narrow REST wrapper in cf_client_live.go.
import _ "github.com/cloudflare/cloudflare-go/v4"
