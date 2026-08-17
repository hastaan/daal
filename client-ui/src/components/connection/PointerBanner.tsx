// PointerBanner — gold-tinted banner showing pointer rotation status.
//
// Honesty rule (see D2Contract's PointerRotationSummary): this banner
// used to open with "Pointers rotated successfully." on every device,
// because the backend defaulted a missing `ok` field to true. The engine
// struct has no such field and most devices have never rotated anything.
// What the engine DOES report is which pointer set the next boot will
// use, and when it expires — so that is what this renders, and when a
// piece is missing it says so instead of filling in a number.
import type { Locale } from '../../lib/i18n';
import type { PointerRotationSummary } from '../../contract/D2Contract';
import { NumeralSpan } from '../atoms';

interface Props {
    data: PointerRotationSummary | null;
    locale: Locale;
    t: (k: string) => string;
}

export default function PointerBanner({ data, locale, t }: Props) {
    if (!data) return null;
    const days = data.validForDays;
    return (
        <div className="d2-pointer-banner">
            <strong>{t('banner_label')}</strong>
            <span>
                {data.primarySource === 'persisted'
                    ? t('banner_source_persisted')
                    : data.primarySource === 'embedded'
                    ? t('banner_source_embedded')
                    : t('banner_source_unknown')}
                {' '}
                {typeof days === 'number' ? (
                    days >= 0 ? (
                        <>
                            {t('banner_valid_pre')}{' '}
                            <NumeralSpan locale={locale}>{days}</NumeralSpan>{' '}
                            {t('banner_valid_post')}
                        </>
                    ) : (
                        // A negative horizon is a measured fact, not a
                        // missing one — never round it up to "valid".
                        t('banner_valid_expired')
                    )
                ) : (
                    t('banner_valid_unknown')
                )}
            </span>
        </div>
    );
}
