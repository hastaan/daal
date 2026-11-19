# Farsi style for Daal

The owner, a native speaker, read the app on a phone and said the Farsi "is not natural", e.g. «ضربه بزنید». The current text is grammatical but reads as translated English. Your job is to make each string read as if a careful Iranian product writer had written it in Persian first, for an ordinary person inside Iran with no technical knowledge (think of the tone of a good Iranian banking or messaging app: polite, plain, short).

## How to work

- Read the English for the MEANING, then write the Persian sentence a person would actually say. Do not mirror English word order, passives, or noun chains.
- Short sentences. Prefer verbs to verbal nouns («وصل شوید», not «اتصال را برقرار کنید»). Drop words Persian does not need («در حال …» chains, «توسط», «جهت», «می‌باشد», «نمایید»).
- Address the person as «شما» with ordinary polite imperatives («بزنید», «صبر کنید», «دوباره امتحان کنید»). Not bookish, not slang, no «تو».
- Buttons and menu labels: as short as Iranian apps make them («ادامه», «ذخیره», «حذف», «بستن», «تلاش دوباره», «بعداً», «باشه» is too casual: use «تأیید» or the action itself).
- Never change the meaning. Never drop or soften a warning, a cost, a security statement or a limit ("as far as this phone can tell" must stay hedged). Never add a promise the English does not make.
- No protocol names or jargon that the English does not have. Where the English is itself technical (some Settings and diagnostics strings), keep the technical token in Latin and make the rest plain.

## Calques to remove (examples, not a complete list)

| Seen | Write instead |
|---|---|
| ضربه بزنید / لمس کنید | بزنید («روی «افزودن» بزنید», «… را بزنید») |
| برون‌بری / درون‌ریزی | خروجی گرفتن یا ذخیره / وارد کردن |
| در حال چرخش… / در حال بررسی … و پرسیدن اینکه… | «کمی صبر کنید…» or the plain action: «دارد بررسی می‌کند…» |
| برنامه‌ها خودشان تغییر را برمی‌دارند | برنامه‌ها خودشان به‌روز می‌شوند |
| حامل (transport) | روش اتصال / راه |
| مهر شده (sealed) | قفل شده / فقط برای … ساخته شده |
| ارائه می‌دهد / ارائه نمی‌دهد | دارد / دیگر ندارد / فعال است |
| به آنچه باقی مانده برمی‌گردد | از بقیه استفاده می‌کند |
| تشخیص‌ها (diagnostics) | گزارش عیب‌یابی |
| ناموفق بود | نشد («ذخیره نشد», «وصل نشد») |
| لطفاً … نمایید / می‌باشد | plain «… کنید» / «است» |

## Fixed words (use exactly these, everywhere)

| English | Persian |
|---|---|
| Daal | دال |
| relay | رله |
| publisher | ناشر |
| recipient | گیرنده |
| file | فایل |
| address (any kind: Daal address, web address, server address) | آدرس (not نشانی) |
| phone | گوشی (not تلفن) |
| app | برنامه |
| server | سرور |
| hosting company / provider | شرکت میزبانی |
| hosting account | حساب میزبانی |
| access key (hosting) | کلید دسترسی |
| backup | نسخهٔ پشتیبان (short labels may say «پشتیبان») |
| recovery words | کلمه‌های بازیابی |
| route / way | مسیر / راه (keep what the English distinguishes) |
| connect / connected / disconnect | وصل شدن / وصل است / قطع کردن |
| settings | تنظیمات |
| remove access | قطع دسترسی |
| delete | حذف |
| costs money / billing | هزینه دارد / هزینه |
| QR code | کد QR |
| Details | جزئیات |
| Try again | تلاش دوباره (label) / دوباره امتحان کنید (sentence) |
| Back / Continue / Cancel / Done / Close | برگشت / ادامه / لغو / تمام / بستن |

## Mechanics (a broken string breaks the app)

- Keep every placeholder exactly: `{name}`, `{n}`, `{ip}` and so on, same spelling, same count. Keep `\n` line breaks where they are.
- Keep Latin tokens as they are: file endings (.sbpx, .sbp, .daalbackup), QR, PIN, VPN, Wi-Fi, product and company names, protocol names where the English has them, URLs, email addresses, `daal1…`.
- Keep leading symbols and arrows that are part of a label (●, ↻, ✓, +, →, ←, ▸). In Persian text a "back" arrow points right (→) and a "forward" arrow points left (←); keep whatever direction the current Persian string already uses.
- Use the half-space (ZWNJ, U+200C) correctly: می‌شود، نمی‌تواند، فایل‌ها، آن‌ها، به‌روز، راه‌اندازی. Use «» for quoted labels, and Persian punctuation ، ؛ ؟ . Keep an ellipsis as the single character … where the current string has it.
- Digits: keep the kind of digits the current Persian string uses (Persian ۰-۹ in prose; Latin inside technical tokens and placeholders).
- No Latin letters transliterated into Persian for technical tokens, and no Arabic ي or ك (use ی and ک).

## What to return

Only the strings you actually improve. A string that already reads naturally stays out of your answer. Do not touch a string just to change a synonym unless the Fixed words table requires it.
