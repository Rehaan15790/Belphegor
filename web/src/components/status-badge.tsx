"use client";

import { useTranslations } from "next-intl";

import { type StatusDomain, statusMeta, toneClasses, toneDot } from "@/lib/status";
import { cn } from "@/lib/utils";

export function StatusBadge({
  domain,
  value,
  dot = false,
  className,
}: {
  domain: StatusDomain;
  value: string;
  dot?: boolean;
  className?: string;
}) {
  const meta = statusMeta(domain, value);
  // Shared status labels live in the "status" message namespace (ko/zh);
  // lib/status.ts only carries the color tone. The raw value is the last-resort
  // fallback for an unknown status (every real status.* key exists in ko/zh).
  const t = useTranslations("status");
  const key = `${domain}.${value}`;
  const label = t.has(key) ? t(key) : value;
  return (
    <span
      className={cn(
        "chamfer inline-flex items-center gap-1.5 border px-2 py-0.5 text-xs font-semibold tracking-wider whitespace-nowrap uppercase [--chamfer:5px]",
        toneClasses[meta.tone],
        className,
      )}
    >
      {dot && <span className={cn("size-1.5 rounded-full", toneDot[meta.tone])} />}
      {label}
    </span>
  );
}
