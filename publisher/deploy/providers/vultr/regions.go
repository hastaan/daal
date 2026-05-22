package vultr

// DefaultRegion is the FRP-Iran-targeted default for Vultr deploys.
// FRA = Frankfurt = principal European peering hub for Iranian
// transit (matches Hetzner's fsn1 default rationale).
const DefaultRegion = "fra"

// SupportedRegions lists Vultr regions the wizard surfaces. Vultr
// publishes more; we narrow to the operationally-relevant subset
// for V2 alpha pilots.
var SupportedRegions = []string{
	"fra", // Frankfurt
	"ams", // Amsterdam
	"lhr", // London
	"par", // Paris
	"sto", // Stockholm
	"waw", // Warsaw
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
