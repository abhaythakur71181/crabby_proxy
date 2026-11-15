// Theme boot — runs before paint to avoid FOUC. "system" tracks the OS.
// Kept as an external, render-blocking classic script (not inline) so the
// Content-Security-Policy in nginx.conf can stay at script-src 'self'.
(function () {
  try {
    var t = localStorage.getItem("cbpx2_theme") || "dark";
    var dark =
      t === "dark" ||
      (t === "system" &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    if (dark) document.documentElement.classList.add("dark");
  } catch (e) {
    document.documentElement.classList.add("dark");
  }
})();
