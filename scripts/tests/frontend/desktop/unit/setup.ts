import "../../../../../apps/desktop/node_modules/@testing-library/jest-dom/vitest.js";
import { afterEach } from "vitest";
import { cleanup } from "../../../../../apps/desktop/node_modules/@testing-library/react";

afterEach(() => {
  cleanup();
});

// JSDOM does not guarantee crypto.randomUUID across environments.
if (!globalThis.crypto) {
  (globalThis as any).crypto = {};
}
if (!(globalThis.crypto as any).randomUUID) {
  (globalThis.crypto as any).randomUUID = () => {
    const s = Math.random().toString(16).slice(2).padEnd(8, "0");
    const t = Math.random().toString(16).slice(2).padEnd(8, "0");
    return `${s}-${t}-test`;
  };
}

const createCanvasContextMock = () =>
  ({
    clearRect: () => {},
    fill: () => {},
    fillRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    drawImage: () => {},
    arc: () => {},
    setTransform: () => {},
    save: () => {},
    restore: () => {},
    fillStyle: "#000",
    strokeStyle: "#000",
    lineWidth: 1,
    lineCap: "",
    lineJoin: "",
    globalAlpha: 1,
  }) as CanvasRenderingContext2D;

Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  writable: true,
  value: createCanvasContextMock,
});
