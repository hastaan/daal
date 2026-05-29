//go:build !soak

package main

func setNow(req request) response {
	return response{ID: req.ID, Error: "set-now requires -tags soak (release builds do not expose clock override)"}
}
