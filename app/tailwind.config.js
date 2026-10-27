/** @type {import('tailwindcss').Config} */
// Colors are CSS variables (see src/styles.css) so one class works in light and dark.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        surface: { DEFAULT: v("surface"), 2: v("surface-2") },
        line: v("line"),
        fg: { DEFAULT: v("fg"), muted: v("fg-muted"), subtle: v("fg-subtle") },
        brand: { DEFAULT: v("brand"), ink: v("brand-ink"), soft: v("brand-soft") },
        ok: { DEFAULT: v("ok"), soft: v("ok-soft") },
        warn: { DEFAULT: v("warn"), soft: v("warn-soft") },
        danger: { DEFAULT: v("danger"), soft: v("danger-soft") },
        info: { DEFAULT: v("info"), soft: v("info-soft") },
        violet: { DEFAULT: v("violet"), soft: v("violet-soft") },
      },
      borderRadius: {
        card: "16px",
      },
      boxShadow: {
        card: "0 1px 2px rgb(16 24 40 / 0.04), 0 1px 3px rgb(16 24 40 / 0.06)",
        "card-hover": "0 8px 24px -6px rgb(16 24 40 / 0.12)",
        hero: "0 18px 40px -18px rgb(var(--brand) / 0.45)",
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "'Segoe UI'", "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
