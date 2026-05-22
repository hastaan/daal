// Input — text input matching the surface treatment of cards.

import { forwardRef, type InputHTMLAttributes } from 'react';

interface Props extends InputHTMLAttributes<HTMLInputElement> {
    invalid?: boolean;
}

export const Input = forwardRef<HTMLInputElement, Props>(function Input(
    { invalid, style, ...rest },
    ref,
) {
    return (
        <input
            ref={ref}
            {...rest}
            style={{
                width: '100%',
                background: 'var(--bg)',
                border: `1px solid ${
                    invalid ? 'var(--red)' : 'var(--line)'
                }`,
                color: 'var(--fg)',
                padding: '10px 12px',
                borderRadius: 'var(--radius-md)',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                outline: 'none',
                ...style,
            }}
        />
    );
});
