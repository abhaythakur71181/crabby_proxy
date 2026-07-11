import { useCallback, useEffect, useSyncExternalStore } from "react";

export type Theme = "dark" | "light" | "system";
const KEY = "cbpx2_theme";

const listeners = new Set<() => void>();
let current: Theme = (localStorage.getItem(KEY) as Theme) || "dark";

function apply(theme: Theme) {
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

export function useTheme() {
  const theme = useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => current,
  );

  const setTheme = useCallback((t: Theme) => {
    current = t;
    localStorage.setItem(KEY, t);
    apply(t);
    listeners.forEach((l) => l());
  }, []);

  // Track OS changes while in system mode.
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => current === "system" && apply("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  return { theme, setTheme };
}
