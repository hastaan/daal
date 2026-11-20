// uiText — the few words a primitive says by itself (a close button's
// name), in the language the app is showing. Pages pass their own
// strings; this is only for the `ui.*` keys a primitive needs when the
// caller gave none.

import { translate } from '../../lib/i18n';
import type { Locale } from '../../lib/i18n';

export function docLocale(): Locale {
    try {
        const lang = document.documentElement.getAttribute('lang') ?? '';
        if (lang.toLowerCase().startsWith('fa')) return 'fa';
        if (document.documentElement.getAttribute('dir') === 'rtl') return 'fa';
    } catch {
        /* no document (tests): English */
    }
    return 'en';
}

export function uiText(key: string): string {
    return translate(docLocale(), key);
}
