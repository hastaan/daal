# Probe-Report Reviewer Checklist

Before a contributed report is added as a fixture, a reviewer confirms:

- [ ] No exact IP appears anywhere in the file.
- [ ] No SSID/BSSID/carrier numeric ID appears.
- [ ] `country_hint` is at country granularity only.
- [ ] `carrier_class` is one of the allowed coarse buckets.
- [ ] `notes` is empty or contains only generic text approved by the contributor.
- [ ] No persistent identifier carries across reports.
- [ ] No timestamp finer than hour granularity.
- [ ] Categories listed appear in `specs/failure-taxonomy-v1.md`.
- [ ] No real route secrets or real CDN IPs.
- [ ] Contributor has confirmed sharing.

If any item fails, the report is not added as a fixture.
