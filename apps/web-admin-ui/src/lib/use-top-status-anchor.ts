import { useCallback, useLayoutEffect, useRef } from "react";
import type { RefObject } from "react";
import { useSetAtom } from "jotai";
import { setToastAnchorAtom } from "@/stores/toastAtom";

type AnchorElement = HTMLElement | null;

export function useTopStatusAnchor(
  actionsRef: RefObject<AnchorElement>,
  contentRef?: RefObject<AnchorElement>,
) {
  const setToastAnchor = useSetAtom(setToastAnchorAtom);
  const rafRef = useRef<number | null>(null);

  const syncNow = useCallback(() => {
    const actionsRect = actionsRef.current?.getBoundingClientRect();
    if (!actionsRect) {
      return;
    }
    const mainFromActions =
      actionsRef.current?.closest("main") instanceof HTMLElement
        ? (actionsRef.current?.closest("main") as HTMLElement)
        : null;
    const contentRect =
      contentRef?.current?.getBoundingClientRect() ??
      mainFromActions?.getBoundingClientRect() ??
      null;
    const x = contentRect
      ? Math.round(contentRect.left + contentRect.width / 2)
      : Math.round(actionsRect.left + actionsRect.width / 2);
    const y = Math.round(actionsRect.top + actionsRect.height / 2);
    setToastAnchor({ x, y });
  }, [actionsRef, contentRef, setToastAnchor]);

  const scheduleSync = useCallback(() => {
    if (rafRef.current !== null) return;
    rafRef.current = window.requestAnimationFrame(() => {
      rafRef.current = null;
      syncNow();
    });
  }, [syncNow]);

  useLayoutEffect(() => {
    syncNow();
    scheduleSync();
    window.addEventListener("resize", scheduleSync);
    window.addEventListener("scroll", scheduleSync, true);

    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(() => scheduleSync());
      if (actionsRef.current) observer.observe(actionsRef.current);
      if (contentRef?.current) observer.observe(contentRef.current);
      const mainFromActions =
        actionsRef.current?.closest("main") instanceof HTMLElement
          ? (actionsRef.current?.closest("main") as HTMLElement)
          : null;
      if (mainFromActions) observer.observe(mainFromActions);
    }

    return () => {
      window.removeEventListener("resize", scheduleSync);
      window.removeEventListener("scroll", scheduleSync, true);
      if (observer) observer.disconnect();
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [actionsRef, contentRef, scheduleSync, syncNow]);
}
