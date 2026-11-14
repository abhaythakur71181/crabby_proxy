// Tiny external store so any component (topbar) can open the ⌘K palette.
// Kept out of command-palette.tsx so that file only exports components
// (required for React fast refresh).
import { useSyncExternalStore } from "react";

let isOpen = false;
const listeners = new Set<() => void>();

export function isPaletteOpen() {
  return isOpen;
}

export function setPaletteOpen(v: boolean) {
  isOpen = v;
  listeners.forEach((l) => l());
}

export function openPalette() {
  setPaletteOpen(true);
}

export function usePaletteOpen() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    isPaletteOpen,
  );
}
