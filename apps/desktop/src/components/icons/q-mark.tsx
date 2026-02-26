import { cn } from "@/lib/utils";

interface QMarkProps {
  className?: string;
  size?: number;
}

export function QMark({ className, size = 24 }: QMarkProps) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("shrink-0", className)}
    >
      <path
        fillRule="evenodd"
        d="M25 13a12 12 0 10-24 0 12 12 0 0024 0zM6 13a7 7 0 1114 0 7 7 0 01-14 0z"
      />
      <path d="M18.5 15.5L30.5 30 15 25z" />
    </svg>
  );
}

export function QMarkFull({ className, size = 32 }: QMarkProps) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("shrink-0", className)}
    >
      <rect x="0.5" y="0.5" width="31" height="31" rx="7" fill="currentColor" fillOpacity="0.08" stroke="currentColor" strokeOpacity="0.15" />
      <g transform="translate(3 3) scale(0.81)" fill="currentColor">
        <path
          fillRule="evenodd"
          d="M25 13a12 12 0 10-24 0 12 12 0 0024 0zM6 13a7 7 0 1114 0 7 7 0 01-14 0z"
        />
        <path d="M18.5 15.5L30.5 30 15 25z" />
      </g>
    </svg>
  );
}
