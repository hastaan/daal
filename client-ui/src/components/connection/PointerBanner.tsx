// PointerBanner — gold-tinted banner showing pointer rotation status.
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
    return (
        <div className="d2-pointer-banner">
            <strong>{t('banner_label')}</strong>
            <span>
                {data.rotatedSuccessfully
                    ? t('banner_rotated_ok_pre')
                    : t('banner_rotated_failed_pre')}
                {' '}
                {data.validForDays > 0 && (
                    <>
                        {t('banner_valid_pre')}{' '}
                        <NumeralSpan locale={locale}>{data.validForDays}</NumeralSpan>{' '}
                        {t('banner_valid_post')}
                    </>
                )}
            </span>
        </div>
    );
}
