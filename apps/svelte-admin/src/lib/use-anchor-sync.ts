import { setAnchor } from "@quicfuscate/ui";

/**
 * Tracks an element's position and updates the toast anchor point.
 * Attaches resize/scroll listeners and a ResizeObserver for live tracking.
 * Returns a cleanup function for use inside Svelte 5 `$effect()`.
 *
 * Usage: `$effect(() => useAnchorSync(actionsEl));`
 */
export function useAnchorSync(
  element: HTMLDivElement | undefined,
): (() => void) | void {
  if (!element) return;

  const sync = () => {
    if (!element) return;
    const rect = element.getBoundingClientRect();
    const main = element.closest("main");
    const mainRect = main instanceof HTMLElement ? main.getBoundingClientRect() : null;
    const x = mainRect
      ? Math.round(mainRect.left + mainRect.width / 2)
      : Math.round(rect.left + rect.width / 2);
    const y = Math.round(rect.top + rect.height / 2);
    setAnchor({ x, y });
  };

  sync();
  window.addEventListener("resize", sync);
  window.addEventListener("scroll", sync, true);

  let observer: ResizeObserver | null = null;
  if (typeof ResizeObserver !== "undefined") {
    observer = new ResizeObserver(() => sync());
    observer.observe(element);
    const main = element.closest("main");
    if (main instanceof HTMLElement) observer.observe(main);
  }

  return () => {
    window.removeEventListener("resize", sync);
    window.removeEventListener("scroll", sync, true);
    observer?.disconnect();
  };
}
