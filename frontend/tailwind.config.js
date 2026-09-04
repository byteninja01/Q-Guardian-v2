/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        pnb: {
          maroon: "#A20C39",
          gold: "#FBBC09",
          light: "#DBE9F4",
          dark: "#1e293b",
        }
      },
      fontFamily: {
        sans: ['Arial', 'ui-sans-serif', 'system-ui'],
      }
    },
  },
  plugins: [],
}
