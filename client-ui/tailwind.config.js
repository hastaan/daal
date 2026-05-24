/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Material-aligned tokens to match the Compose UI from Phase 1B.
        accent: '#6750a4',
        warning: '#b3261e',
        ok: '#1f7a3a',
        bg: '#fffbfe',
        fg: '#1c1b1f',
      },
    },
  },
  plugins: [],
};
