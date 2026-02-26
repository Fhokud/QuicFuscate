import { Component, ReactNode } from "react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex flex-col items-center justify-center h-full min-h-[300px] gap-4 p-8">
          <div className="w-16 h-16 rounded-2xl bg-negative-muted border border-negative/20 flex items-center justify-center">
            <svg
              className="w-8 h-8 text-negative"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
              />
            </svg>
          </div>
          <div className="text-center space-y-2">
            <h2 className="text-[14px] font-semibold text-text-primary">
              Something went wrong
            </h2>
            <p className="text-[12px] text-text-secondary max-w-[320px]">
              An unexpected error occurred. The application may need to be restarted.
            </p>
            {this.state.error && (
              <p className="text-[11px] text-text-ghost font-mono max-w-[400px] break-words">
                {this.state.error.message}
              </p>
            )}
          </div>
          <div className="flex items-center gap-3">
            <Button
              type="button"
              onClick={this.handleRetry}
              className="inline-flex items-center rounded-lg border transition-all action-refresh-btn"
              size="sm"
            >
              Try Again
            </Button>
            <Button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center rounded-lg border transition-all action-save-btn"
              size="sm"
            >
              Restart App
            </Button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
