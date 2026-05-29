# Daal V1.5 Pilot Consent Template

**Status:** template (committed; signed/filled copies are
**NOT** committed — they are private personal records, see
`.gitignore`).

**Versioning:** this template is referenced by version. The git
SHA at the time of signing is the binding version. Updates to
this template never retroactively bind a prior signature.

**Two-language requirement:** the consent text is published in
English (operational lingua franca for the project) and Persian
(the recipient population's language). The Persian text below
is a first-pass translation and is marked `NEEDS NATIVE
REVIEW` until a native speaker reviews it. **A pilot operator
SHOULD NOT use the Persian copy for an unreviewed launch.**

---

## English consent text

I, the undersigned **Family Relay Publisher** (FRP) for the
Daal anti-censorship pilot, agree to the following on behalf
of myself and (where applicable) the recipients I introduce to
the pilot:

### What this pilot is

The Daal project is a free and open-source anti-censorship
client. The V1.5 pilot tests whether a diaspora-based operator
can stand up a Hetzner VPS, generate a signed RelayPack, and
keep one or more family members in a censored country online for
at least seven consecutive days using only the shipped tooling.

### What data is collected

The pilot evidence template (`docs/pilot/frp-7-pilot-template.md`)
collects only **operational measurements**:

* Provisioning wall-clock duration.
* Recipient connect-time wall-clock duration.
* Aggregate uptime percentage over seven simulated days.
* Number and type of rotations observed.
* Whether the recipient saw a plain-language explanation when a
  rotation occurred.
* Free-text observations about UX, copy, packaging issues.

### What data is NOT collected

The pilot evidence template does NOT collect — and the FRP
agrees not to record in it — any of:

* Real names of the FRP, the recipients, or third parties.
* Phone numbers, email addresses, postal addresses.
* Cloud-provider account identifiers, API tokens, billing data.
* Server IP addresses, ASN identifiers, or DNS records.
* Publisher private keys (these never leave the FRP machine in
  any case; the V1.5 wizard's keystore enforces this).
* Recipient device identifiers, IMEIs, or installed-app lists.
* The contents of any traffic carried over the relay.

The Daal engine itself does **not** phone home (Position B —
`daal-roadmap-v3-supplement-diaspora-helper.md` §13). This
consent applies only to the FRP-side evidence template.

### Pilot duration

Seven consecutive days of normal use, plus up to seven
additional days for the operator to fill in the template. The
FRP may withdraw at any point during or after this window.

### Withdrawal

The FRP may withdraw at any time, for any reason, without
explanation. Withdrawal means: stop running the relay, stop
filling out the template, send any unfinished template back to
the project lead with a note saying "withdraw". Already-
collected evidence will be discarded on the FRP's request.

### Contact and escalation

The project lead is the named recipient on the inside cover of
this consent template (filled in at the time of signing). The
FRP may contact the project lead through the agreed-upon
channel (typically Signal at a number exchanged out-of-band).

### Signature and date

| Field | Value |
|---|---|
| FRP pseudonym (no real name) | `frp-X` |
| Date (UTC) | `YYYY-MM-DD` |
| Template git SHA at signing | `<sha>` |
| FRP signature (initials only) | |
| Project lead countersignature | |

---

## V1.6 CDN-fronted supplement

This section applies only when the FRP participates in the FRP-9
V1.6 CDN-fronted alpha pilot.

### Additional pilot behaviour

The V1.6 pilot adds a CDN-fronted RelayPack candidate controlled by
the FRP. The recipient may connect to a hostname under the FRP's own
domain, fronted by Cloudflare, and the FRP may rotate the public path,
hostname, or hidden origin during the pilot.

### Additional data in the evidence template

The FRP-9 evidence template (`docs/pilot/frp-9-pilot-template.md`)
adds only operational measurements:

* Whether a recipient connected through a `cdn_fronted` candidate
  within the time budget.
* Whether a public-surface rotation recovered through the freshness
  endpoint without a QR re-scan.
* Whether an origin-only rotation caused zero family-visible event.
* Whether the CDN posture check passed at the beginning and end of the
  pilot.

### Additional data that must NOT be recorded

The FRP agrees not to record Cloudflare account IDs, API tokens,
origin IP addresses, DNS history, actual hostnames, server IPs, ASNs,
recipient device identifiers, or traffic contents in the filled
template. The freshness URL is FRP-controlled; the Daal project does
not operate a freshness host for this pilot.

### V1.6 withdrawal

The FRP may withdraw from the CDN-fronted pilot at any time. Withdrawal
means disabling the CDN front, stopping the pilot evidence template,
and asking the project lead to discard any unfinished aggregate row if
desired.

---

## متن رضایت‌نامه فارسی *(NEEDS NATIVE REVIEW)*

> این بخش به عنوان نسخه اولیه ارائه شده و **پیش از استفاده باید
> توسط یک گویشور بومی فارسی بازبینی شود**. تا زمان بازبینی، از
> این متن برای امضا استفاده نکنید.

من، امضاکننده زیر، به‌عنوان **منتشرکنندهٔ رلهٔ خانوادگی** (FRP)
در پایلوت ضدسانسور Daal، با موارد زیر موافقم:

### این پایلوت چیست

پروژهٔ Daal یک کلاینت ضدسانسور آزاد و متن‌باز است. پایلوت V1.5
بررسی می‌کند که آیا یک کاربر در دیاسپورا می‌تواند یک VPS در
Hetzner راه‌اندازی کند، یک RelayPack امضا‌شده تولید کند، و یک یا
چند عضو خانواده‌اش را در یک کشور سانسورشده برای حداقل هفت روز
متوالی فقط با ابزارهای ارائه‌شده آنلاین نگه دارد.

### چه داده‌هایی جمع‌آوری می‌شود

قالب شواهد پایلوت (`docs/pilot/frp-7-pilot-template.md`) فقط
**اندازه‌گیری‌های عملیاتی** را جمع می‌کند:

* مدت زمان راه‌اندازی.
* مدت زمان اتصال گیرنده.
* درصد آپ‌تایم تجمیعی طی هفت روز شبیه‌سازی‌شده.
* تعداد و نوع چرخش‌های مشاهده‌شده.
* اینکه آیا گیرنده یک توضیح به زبان ساده در زمان چرخش دید.
* مشاهدات متن آزاد دربارهٔ تجربه کاربری، متن، یا مشکلات بسته‌بندی.

### چه داده‌هایی جمع‌آوری **نمی‌شود**

قالب شواهد پایلوت هیچ‌کدام از موارد زیر را جمع نمی‌کند، و FRP
موافقت می‌کند که آن‌ها را در قالب ثبت نکند:

* نام واقعی FRP، گیرندگان، یا اشخاص ثالث.
* شماره تلفن، نشانی ایمیل، نشانی پستی.
* شناسه‌های حساب ارائه‌دهندهٔ ابر، توکن‌های API، داده‌های مالی.
* نشانی IP سرور، شناسه‌های ASN، یا رکوردهای DNS.
* کلیدهای خصوصی منتشرکننده.
* شناسه‌های دستگاه گیرنده، IMEI، یا فهرست برنامه‌های نصب‌شده.
* محتوای هرگونه ترافیک منتقل‌شده از رله.

### مدت پایلوت

هفت روز متوالی استفاده عادی، به‌علاوه حداکثر هفت روز اضافی برای
پر کردن قالب توسط اپراتور. FRP می‌تواند هر زمانی در طول یا پس از
این بازه انصراف دهد.

### انصراف

FRP می‌تواند هر زمانی، به هر دلیلی، بدون توضیح انصراف دهد.
انصراف یعنی: اجرای رله را متوقف کنید، پر کردن قالب را متوقف
کنید، هر قالب ناتمام را با یادداشت "انصراف" به سرپرست پروژه
بازگردانید. شواهد قبلاً جمع‌شده در صورت درخواست FRP حذف خواهد شد.

### تماس و ارجاع

سرپرست پروژه گیرندهٔ نام‌برده در جلد داخلی این قالب رضایت‌نامه
است (در زمان امضا تکمیل می‌شود). FRP می‌تواند از طریق کانال
توافق‌شده (معمولاً Signal با شماره‌ای که به‌صورت خارج از باند
رد و بدل شده) با سرپرست پروژه تماس بگیرد.

### امضا و تاریخ

| فیلد | مقدار |
|---|---|
| نام مستعار FRP (بدون نام واقعی) | `frp-X` |
| تاریخ (UTC) | `YYYY-MM-DD` |
| Git SHA قالب در زمان امضا | `<sha>` |
| امضای FRP (فقط حروف اول) | |
| امضای متقابل سرپرست پروژه | |

---

## How to use this template

1. Copy this file into `docs/pilot/signed/<frp-id>-consent.md`
   (the `.gitignore` rule keeps `signed/` and `private/`
   directories out of the repo).
2. Fill in the FRP pseudonym, date, and the git SHA of this
   template at the time of signing.
3. Both parties initial the EN section. The FA section is for
   reference; it is the FRP's choice which language they
   consider authoritative for their own records.
4. Keep the signed copy in the project's private storage
   (out-of-tree, encrypted at rest).
5. Aggregate consent counts (e.g. "5 of 5 FRPs signed") may be
   cited in `specs/v1-5-closure-v1.md`; **no individual signed
   consent form, even anonymized, is committed to the repo**.
