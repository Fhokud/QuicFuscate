import React from "react";
import ReactDOM from "react-dom/client";
import { HeroUIProvider } from "@heroui/react";
import { App } from "./App";
import { ErrorBoundary } from "./components/error-boundary";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HeroUIProvider disableRipple={false} disableAnimation={false}>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </HeroUIProvider>
  </React.StrictMode>,
);
