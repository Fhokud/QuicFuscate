import * as React from "react";
import { Tooltip as HeroTooltip, type TooltipProps as HeroTooltipProps } from "@heroui/react";

type TooltipProviderProps = {
  /**
   * Radix compatibility: default delay for tooltips.
   * HeroUI uses `delay` per tooltip; we forward this as a default.
   */
  delayDuration?: number;
  children: React.ReactNode;
};

const TooltipDelayContext = React.createContext<number>(0);

function TooltipProvider({ delayDuration = 0, children }: TooltipProviderProps) {
  return (
    <TooltipDelayContext.Provider value={delayDuration}>
      {children}
    </TooltipDelayContext.Provider>
  );
}

type TooltipRootProps = Omit<HeroTooltipProps, "content" | "children"> & {
  children: React.ReactNode;
};

type TooltipTriggerProps = {
  asChild?: boolean;
  children: React.ReactElement;
};

function TooltipTrigger(_props: TooltipTriggerProps) {
  // Declarative-only. Tooltip() extracts and renders it through HeroUI.
  return null;
}

type TooltipContentProps = {
  children: React.ReactNode;
};

function TooltipContent(_props: TooltipContentProps) {
  // Declarative-only. Tooltip() extracts and renders it through HeroUI.
  return null;
}

function Tooltip({ children, ...props }: TooltipRootProps) {
  const defaultDelay = React.useContext(TooltipDelayContext);

  let trigger: React.ReactElement | null = null;
  let content: React.ReactNode = null;

  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return;
    if (child.type === TooltipTrigger) {
      trigger = (child.props as TooltipTriggerProps).children;
      return;
    }
    if (child.type === TooltipContent) {
      content = (child.props as TooltipContentProps).children;
    }
  });

  if (!trigger || content == null) {
    return null;
  }

  return (
    <HeroTooltip
      delay={defaultDelay}
      content={content}
      {...props}
    >
      {trigger}
    </HeroTooltip>
  );
}

export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider };
