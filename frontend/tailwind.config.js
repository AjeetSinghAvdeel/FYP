/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyberspace: {
          900: '#06121d',
          800: '#10263b',
          700: '#183a56',
          600: '#285a7d',
          500: '#2d9cdb',
          400: '#5ec7ff',
          300: '#9ce6ff',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(94,199,255,0.4), 0 15px 35px rgba(18,39,61,0.35)',
      },
    },
  },
  plugins: [],
}
