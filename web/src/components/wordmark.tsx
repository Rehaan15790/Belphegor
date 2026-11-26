import { cn } from "@/lib/utils";

// Brand wordmark: "BELPHE" in the primary red, "GOR" in the text color.
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-black uppercase tracking-[0.2em]", className)}>
      <span className="text-primary">Belphe</span>gor
    </span>
  );
}
