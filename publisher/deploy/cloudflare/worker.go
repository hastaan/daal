package cloudflare

import "fmt"

// RewriteWorkerScript returns the Cloudflare Worker source that
// rewrites a request whose path starts with publicPath into a
// request whose path starts with originPath, then forwards
// everything else (method, body, query string) unchanged. This
// implements the §11.7 "public random path → stable origin path
// indirection" property so public-path rotation is a
// Cloudflare-API-only operation: the wizard issues a new public
// path, uploads a fresh worker (or re-uploads the same script
// with a new pattern), and the box config — which only knows
// about originPath — does not change.
//
// The Worker is intentionally tiny so a future audit can reason
// about its full behaviour at a glance.
func RewriteWorkerScript(publicPath, originPath string) []byte {
	return []byte(fmt.Sprintf(`addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const publicPath = %q;
  const originPath = %q;
  if (url.pathname === publicPath || url.pathname.startsWith(publicPath + "/")) {
    url.pathname = originPath + url.pathname.slice(publicPath.length);
    const req = new Request(url.toString(), event.request);
    event.respondWith(fetch(req));
    return;
  }
  // Non-rewrite paths: 404 by default; the FRP can extend this
  // if they want a static landing page on their own zone.
  event.respondWith(new Response("not found", { status: 404 }));
});
`, publicPath, originPath))
}
