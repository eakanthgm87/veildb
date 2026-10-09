/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Render-style violet accent.
        primary: {
          50: "#f5f3ff",
          100: "#ede9fe",
          200: "#ddd6fe",
          300: "#c4b5fd",
          400: "#a78bfa",
          500: "#8b5cf6",
          600: "#7c3aed",
          700: "#6d28d9",
          800: "#5b21b6",
          900: "#4c1d95",
        },
        // Render's mint/teal signal color.
        mint: {
          300: "#6ee7c7",
          400: "#46e3b7",
          500: "#2dd4bf",
        },
        // Pure-black surfaces (app bg → elevated).
        dark: {
          900: "#000000",
          800: "#0b0b0d",
          700: "#141417",
          600: "#1d1d21",
        },
        // Cool neutral grays (text + borders).
        slate: {
          100: "#f4f4f5",
          200: "#e4e4e7",
          300: "#c7c7cd",
          400: "#8a8a93",
          500: "#5f5f68",
          600: "#2a2a30",
          700: "#1e1e23",
          800: "#161619",
          900: "#0b0b0d",
        },
      },
      // Square by default — rounded-* collapse to a crisp 2px, only
      // rounded-full stays a pill (badges/avatars).
      borderRadius: {
        none: "0",
        sm: "2px",
        DEFAULT: "2px",
        md: "2px",
        lg: "2px",
        xl: "2px",
        "2xl": "3px",
        "3xl": "4px",
        full: "9999px",
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(139,92,246,0.15), 0 20px 60px -20px rgba(124,58,237,0.5)",
        panel: "0 10px 40px -15px rgba(0,0,0,0.8)",
      },
      backgroundImage: {
        // Headline gradient: violet → lavender → mint (the Render look).
        "brand-gradient": "linear-gradient(100deg,#8b5cf6 0%,#a78bfa 45%,#46e3b7 100%)",
      },
    },
  },
  plugins: [],
};
