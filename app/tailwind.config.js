/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e14",
        surface: "rgba(22, 27, 34, 0.7)",
        border: "rgba(255,255,255,0.08)",
        accent: "#2f81f7",
        "accent-hover": "#4c9bff",
        ok: "#3fb950",
        warn: "#d29922",
        danger: "#f85149",
        crit: "#ff5b52",
        muted: "#8b949e",
        fg: "#e6edf3",
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glass: "0 8px 32px rgba(0,0,0,0.37)",
        glow: "0 0 24px rgba(47,129,247,0.35)",
      },
      backdropBlur: {
        xs: "2px",
      },
      keyframes: {
        "pulse-ring": {
          "0%": { transform: "scale(0.9)", opacity: "0.7" },
          "70%": { transform: "scale(1.3)", opacity: "0" },
          "100%": { opacity: "0" },
        },
      },
      animation: {
        "pulse-ring": "pulse-ring 2s cubic-bezier(0.4,0,0.6,1) infinite",
      },
    },
  },
  plugins: [],
};
