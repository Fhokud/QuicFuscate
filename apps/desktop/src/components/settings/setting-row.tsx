import { cn } from "@/lib/utils";

interface SettingRowProps {
  label: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}

export function SettingRow({ label, description, children, className }: SettingRowProps) {
  return (
    <div className={cn(
      "flex items-center justify-between gap-4 py-2 px-0",
      "border-b border-edge/55 last:border-b-0",
      className,
    )}>
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="text-[11px] font-semibold text-black dashboard-heading-sans">{label}</span>
        {description && (
          <span className="text-[10px] text-black leading-tight">{description}</span>
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
    <section className={cn("rounded-xl glass border border-edge/70", className)}>
      <div className="pane-header border-b border-edge">
        <div className="text-[11px] font-semibold text-black dashboard-heading-sans">{title}</div>
      </div>
      <div className="pane-body pane-first-item-offset">
        <div className="space-y-0">
          {children}
        </div>
      </div>
    </section>
  );
}
