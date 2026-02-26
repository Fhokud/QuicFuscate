import { useLayoutEffect, useState } from "react";

const APP_STAGE_SELECTOR = "#qf-app-stage";

export function useStageModalPortal() {
  const [container, setContainer] = useState<Element | undefined>(undefined);

  useLayoutEffect(() => {
    setContainer(document.querySelector(APP_STAGE_SELECTOR) ?? undefined);
  }, []);

  return container;
}
