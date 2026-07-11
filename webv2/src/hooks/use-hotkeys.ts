// Global keyboard shortcuts: ⌘K / Ctrl+K (palette, handled by the palette
// itself) plus Linear-style "g" chords for navigation.
import { useEffect } from "react";
import { useNavigate } from "react-router";

const CHORDS: Record<string, string> = {
  d: "/dashboard",
  c: "/connections",
  u: "/users",
  g: "/groups",
  t: "/tunnels",
  a: "/approvals",
  l: "/audit",
  s: "/usage",
  h: "/system-health",
  o: "/config",
  m: "/account",
};

function inEditable(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  return (
    el.isContentEditable ||
    ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) ||
    el.closest("[cmdk-root]") != null
  );
}

export function useNavChords(enabled: boolean) {
  const navigate = useNavigate();
  useEffect(() => {
    if (!enabled) return;
    let pendingG = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || inEditable(e.target)) return;
      if (pendingG) {
        pendingG = false;
        clearTimeout(timer);
        const to = CHORDS[e.key.toLowerCase()];
        if (to) {
          e.preventDefault();
          navigate(to);
        }
        return;
      }
      if (e.key.toLowerCase() === "g") {
        pendingG = true;
        timer = setTimeout(() => (pendingG = false), 1200);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      clearTimeout(timer);
    };
  }, [enabled, navigate]);
}
