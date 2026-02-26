export function Titlebar() {
  return (
    <header className="flex items-center justify-between h-6 px-4 glass border-b border-edge select-none shrink-0">
      <span className="text-[9px] font-medium text-text-ghost/60 tracking-widest dashboard-heading-sans">
        QuicFuscate
      </span>
      <span className="text-[9px] text-text-ghost/40 tabular-nums">
        v0.1.0
      </span>
    </header>
  );
}
