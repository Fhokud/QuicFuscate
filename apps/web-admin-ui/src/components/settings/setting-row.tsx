import { cn } from "@/lib/cn";

interface SettingRowProps {
  label: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}

export function SettingRow({ label, description, children, className }: SettingRowProps) {
  return (
    <div className={cn(
      "flex items-center justify-between gap-4 py-2 px-4",
      "border-b border-edge/40 last:border-b-0",
      className,
    )}>
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="text-[12px] text-text-primary">{label}</span>
        {description && (
          <span className="text-[10px] text-text-ghost leading-tight">{description}</span>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

interface SectionProps {
  title: string;
  children: React.ReactNode;
  className?: string;
}

export function SettingSection({ title, children, className }: SectionProps) {
  return (
    <section className={cn("mb-4", className)}>
      <h3 className="text-[10px] font-mono tracking-widest font-medium text-text-ghost px-4 mb-1">
        {title}
      </h3>
      <div className="glass-card rounded-lg border border-edge">
        {children}
      </div>
    </section>
  );
}
