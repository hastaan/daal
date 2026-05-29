// DaalGlyph — the Daal brand mark (a Persian mythical eagle). Two
// variants:
//   * flat   — the 1-color SVG, suitable for nav/sidebar
//   * raster — the rendered PNG, for hero placements
// Both share the same component so screens can switch variants.

import daalFlatUrl from '@branding/sources/daal-eagle.svg?url';
import daalDesktopUrl from '@branding/sources/daal-eagle-transparent.png';

interface Props {
    variant?: 'flat' | 'raster';
    size?: number;
}

export function DaalGlyph({ variant = 'flat', size = 36 }: Props) {
    const src = variant === 'raster' ? daalDesktopUrl : daalFlatUrl;
    return (
        <img
            src={src}
            alt=""
            aria-hidden
            width={size}
            height={size}
            style={{ display: 'block', objectFit: 'contain' }}
        />
    );
}
