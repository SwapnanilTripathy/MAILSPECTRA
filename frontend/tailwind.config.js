/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#050608',
        surface: {
          50: '#1b2630',
          100: '#141b22',
          200: '#0d1117',
          300: '#080c11',
          DEFAULT: '#0d1117',
        },
        border: {
          subtle: '#1c2730',
          DEFAULT: '#293640',
          bright: '#3b5260',
        },
        brand: {
          cyan: '#22bce9',
          blue: '#3b82f6',
          emerald: '#10b981',
          amber: '#f59e0b',
          red: '#ef4444',
          indigo: '#6366f1',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
