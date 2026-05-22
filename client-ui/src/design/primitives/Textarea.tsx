// Textarea — multi-line counterpart to Input.

import { forwardRef, type TextareaHTMLAttributes } from 'react';

interface Props extends TextareaHTMLAttributes<HTMLTextAreaElement> {
    invalid?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, Props>(
    function Textarea({ invalid, style, ...rest }, ref) {
        return (
            <textarea
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
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                    outline: 'none',
                    resize: 'vertical',
                    ...style,
                }}
            />
        );
    },
);
