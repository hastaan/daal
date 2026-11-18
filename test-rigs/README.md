# Daal Test Rigs

This tree contains developer-side test rigs:

- `censor-lab/` — Linux netns rig that simulates Iran-/China-class hostile network behavior and produces failure fixtures.
- `distribution-failure/` — scenarios for blocked distribution channels (Telegram, GitHub, CDNs, app stores, subscription URLs, bootstrap-directory mirrors).
- `worldbox/` — a whole Daal world on one machine (rootless netns): real provisioning, real relay binaries, real engine, a censor in the middle. `./daal e2e` (quick, ~1 min, also the last step of the pre-push hook) or `./daal e2e full` (~5 min). Start here to learn whether a family carries a byte; its `FINDINGS.md` lists every product defect it has exposed.
- `field-probe/` — schema and rules for the privacy-preserving, manually-shared probe report.

Test rigs are not shipped to users. They never collect or upload anything.
