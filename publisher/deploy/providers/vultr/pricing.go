package vultr

// monthlyToHourly converts Vultr's published monthly price to an
// hourly rate using Vultr's standard 730-hour month convention.
func monthlyToHourly(monthly float64) float64 {
	if monthly <= 0 {
		return 0
	}
	return monthly / 730.0
}
