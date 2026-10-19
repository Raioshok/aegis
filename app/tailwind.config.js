/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#F6F8FB",
          muted: "#EDF2F7",
          subtle: "#F1F5F9",
          dark: "#0C0D12",
        },
        surface: {
          DEFAULT: "#FFFFFF",
          hover: "#F8FAFC",
          dark: "#13151D",
          "dark-hover": "#191C26",
        },
        card: {
          DEFAULT: "#FFFFFF",
          dark: "#13151D",
        },
        primary: {
          DEFAULT: "#FF7222",
          hover: "#E85D10",
          light: "#FFF4EC",
          border: "#FFE2CC",
        },
        accent: {
          DEFAULT: "#FF7222",
          hover: "#E85D10",
          light: "#FFF4EC",
        },
        ok: {
          DEFAULT: "#10B981",
          light: "#ECFDF5",
          border: "#A7F3D0",
        },
        warn: {
          DEFAULT: "#F59E0B",
          light: "#FFFBEB",
          border: "#FDE68A",
        },
        danger: {
          DEFAULT: "#EF4444",
          light: "#FEF2F2",
          border: "#FECACA",
        },
        fg: {
          DEFAULT: "#1E293B",
          muted: "#64748B",
          subtle: "#94A3B8",
          dark: "#FFFFFF",
          "dark-muted": "#8491A2",
        },
        border: {
          DEFAULT: "#E8ECF2",
          focus: "#FF7222",
          dark: "#212533",
        },
      },
      boxShadow: {
        card: "0 4px 20px -2px rgba(16, 24, 40, 0.04), 0 2px 6px -1px rgba(16, 24, 40, 0.02)",
        "card-hover": "0 12px 30px -4px rgba(16, 24, 40, 0.08), 0 4px 12px -2px rgba(16, 24, 40, 0.03)",
        button: "0 2px 8px rgba(255, 114, 34, 0.25)",
        pill: "0 2px 6px rgba(0, 0, 0, 0.04)",
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "'Segoe UI'",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
