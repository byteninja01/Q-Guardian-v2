/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          dark: "#0F172A",
          accent: "#6366F1",
          cyan: "#06B6D4",
          emerald: "#10B981",
          light: "#F1F5F9",
        },
        // Alias for smooth theme migration
        pnb: {
          maroon: "#4F46E5", // Modern Indigo
          gold: "#06B6D4",   // Modern Cyan Accent
          light: "#F1F5F9",
          dark: "#0F172A",
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
