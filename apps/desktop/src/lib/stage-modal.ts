import type { ComponentProps } from "react";
import { useLayoutEffect, useState } from "react";
import { Modal } from "@heroui/react";
import { cn } from "@/lib/utils";

const APP_STAGE_SELECTOR = "#qf-app-stage";
const STAGE_MODAL_WRAPPER_CLASS = "qf-stage-modal-wrapper";
const STAGE_MODAL_BACKDROP_CLASS = "qf-stage-modal-backdrop";

type ModalClassNames = ComponentProps<typeof Modal>["classNames"];

export function useStageModalPortal() {
  const [container, setContainer] = useState<Element | undefined>(undefined);

  useLayoutEffect(() => {
    setContainer(document.querySelector(APP_STAGE_SELECTOR) ?? undefined);
  }, []);

  return container;
}

export function withStageModalClassNames(classNames?: ModalClassNames): ModalClassNames {
  return {
    ...classNames,
    wrapper: cn(STAGE_MODAL_WRAPPER_CLASS, classNames?.wrapper),
    backdrop: cn(STAGE_MODAL_BACKDROP_CLASS, classNames?.backdrop),
  };
}
