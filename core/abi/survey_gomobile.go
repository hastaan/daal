//go:build gomobile

package abi

// SurveyRoutes is the gomobile twin of engine_survey_routes.
func (h *DaalCore) SurveyRoutes(start bool) (string, error) {
	return SurveyRoutes(start)
}
