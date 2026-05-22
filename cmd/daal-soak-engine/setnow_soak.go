//go:build soak

package main

import (
	"encoding/json"

	"daal/core/abi"
)

func setNow(req request) response {
	var a struct {
		UnixSeconds int64 `json:"unix_seconds"`
	}
	if err := json.Unmarshal(req.Arg, &a); err != nil {
		return response{ID: req.ID, Error: err.Error()}
	}
	abi.SetNowUnix(a.UnixSeconds)
	return response{ID: req.ID, OK: true}
}
