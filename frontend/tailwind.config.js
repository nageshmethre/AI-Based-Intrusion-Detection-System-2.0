/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        cyber: ['Rajdhani', 'Chakra Petch', 'Inter', 'sans-serif']
      },
      colors: {
        soc: {
          bg: "#050811",
          card: "#070D19",
          border: "#0e223d",
          primary: "#3B82F6",
          accent: "#06B6D4",
          danger: "#EF4444",
          warning: "#F59E0B",
          success: "#10B981",
          muted: "#94A3B8"
        }
      }
    },
  },
  plugins: [],
}
