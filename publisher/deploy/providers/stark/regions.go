package stark

// DefaultRegion is the FRP-Iran-targeted default for Stark deploys.
// Stark's two Lithuanian DCs are off TIC's most aggressive
// blocklists per research/Protocols.md; vno (Vilnius) is the
// principal supplement-§11.6 default.
const DefaultRegion = "vno"

// SupportedRegions: Stark's Lithuanian + EU footprint.
var SupportedRegions = []string{
	"vno", // Vilnius
	"kun", // Kaunas
	"fra", // Frankfurt fallback
}

// IsSupportedRegion reports whether r is in SupportedRegions.
func IsSupportedRegion(r string) bool {
	for _, sr := range SupportedRegions {
		if sr == r {
			return true
		}
	}
	return false
}
