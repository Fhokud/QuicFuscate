import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

type ConnectButtonState = "idle" | "connecting" | "connected" | "disconnecting";

interface ConnectButtonProps {
  state: ConnectButtonState;
  onClick: () => void;
  disabled?: boolean;
  hasQKey?: boolean;
  className?: string;
  buttonClassName?: string;
  hint?: string;
}

export function ConnectButton({
  state,
  onClick,
  disabled = false,
  hasQKey = false,
  className,
  buttonClassName,
  hint,
}: ConnectButtonProps) {
  const isBusy = state === "connecting" || state === "disconnecting";
  const isConnected = state === "connected";
  const isIdle = state === "idle";

  const getButtonText = () => {
    switch (state) {
      case "connecting":
        return "Connecting";
      case "disconnecting":
        return "Stopping";
      case "connected":
        return "Disconnect";
      case "idle":
      default:
        return "Connect";
    }
  };

  const getButtonStyle = () => {
    if (isConnected) {
      return "action-disconnect-btn";
    }
    return "action-save-btn";
  };

  const handleClick = () => {
    if (isBusy || disabled) return;
    if (isIdle && !hasQKey) {
      onClick();
      return;
    }
    onClick();
  };

  return (
    <div className={cn("relative inline-flex flex-col items-center", className)}>
      <Button
        type="button"
        onClick={handleClick}
        disabled={isBusy || disabled}
        className={cn(
          "connect-action-btn relative inline-flex items-center justify-center rounded-lg overflow-hidden",
          "border disabled:opacity-40 disabled:cursor-not-allowed overflow-hidden",
          getButtonStyle(),
          buttonClassName,
        )}
        aria-label={isConnected ? "Disconnect" : hasQKey ? "Connect" : "Set QKey"}
      >
        <span>{getButtonText()}</span>
      </Button>

      {/* Hint text below button */}
      {hint && (
        <p
          className="mt-2 text-[10px] text-text-tertiary text-center max-w-[180px]"
        >
          {hint}
        </p>
      )}
    </div>
  );
}
