//go:build !singbox

package engine

import "errors"

// ProtectFD without sing-box: no in-process data plane, so no callback
// can have been wired to anything; a registered one is a build mistake
// and the socket is refused rather than sent unprotected.
func ProtectFD(int) error {
	if CurrentProtectCallback() == 0 {
		return nil
	}
	return errors.New("engine: protect callback registered but this build has no sing-box")
}
