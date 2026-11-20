# Sealed Report v1

## Status

Built 2026-11-20 (`bundle/go/envelope/report.go`,
`bundle/go/fieldreport`). Used by the network test
(`specs/field-probe-v2.md`).

## Wire format

```
D S B R 0x00 0x01  ‖  age v1 stream (one X25519 recipient)
```

The age layer is the one `.sbpx` uses (`specs/sbpx-envelope-v1.md`); only
the magic differs, so the pack importer refuses a report
(`envelope.Decrypt` → `ErrBadMagic`) and the report opener refuses a pack
(`envelope.DecryptReport` → `ErrNotReport`). Cap: 1 MiB.

## Plaintext

The schema-v2 report JSON (`specs/field-probe-v2.md`), validated before
sealing, then padded with spaces to the next multiple of 16 KiB, so the
file size says nothing about what was found. JSON allows trailing
whitespace; the opener trims it before its strict parse.

## Key

The recipient is the publisher's **report key**, an X25519 key made only
for this (`envelope.NewReportKey`; `daal-deploy report-keygen`). Its
public half is written as a `daal1…` address (the
`specs/recipient-address-v1.md` codec; `fieldreport.EncodeAddress` is a
byte-for-byte copy pinned to the same golden vectors) and carried in the
Test relay routes' `family_specific_config._report_to`. It is not the
publisher's signing key and is not derived from it: the key separation
`recipient-address-v1.md` states is kept.

## File name

`net-<8 random [a-z0-9]>.dat`: no app name, no date.

## Trust

age gives confidentiality and integrity against anyone without the report
key. It gives **no sender authentication**: anyone who has the report
address can make a file that opens. The opener parses strictly (unknown
fields, enums outside the schema, a `variant` with a dot or colon are all
refused) and treats every report as untrusted input, as v1 already says.
