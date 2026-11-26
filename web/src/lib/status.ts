// Centralised status → color semantics, reused across the whole app.
// Spec §8.3: intent / coverage / task / severity each have a consistent color set.
// User-facing labels live in the "status" message namespace (ko/zh); the maps
// here only carry the color tone, keyed by the same status value.

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "violet" | "slate";

export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20",
  green: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  amber: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/20",
  red: "bg-primary/10 text-primary border-primary/50",
  // rose is used for "critical": solid and strongly emphasized, visibly stronger than the soft red outline of "high".
  rose: "bg-primary text-primary-foreground border-primary",
  violet: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/20",
  slate: "bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/20",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-blue-500",
  green: "bg-emerald-500",
  amber: "bg-amber-500",
  red: "bg-primary",
  rose: "bg-primary-foreground",
  violet: "bg-violet-500",
  slate: "bg-slate-500",
};

interface StatusMeta {
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { tone: "slate" },
  running: { tone: "blue" },
  paused: { tone: "amber" },
  done: { tone: "green" },
  // blocked = model/API/network failure with retries exhausted; this intent was basically never actually explored (not a target intercept).
  blocked: { tone: "red" },
  // exhausted = cut off midway on reaching the step/time budget, only partial results written back (not that the direction is fully explored).
  exhausted: { tone: "violet" },
  // stopped = legacy soft-delete state (kept, historical data).
  stopped: { tone: "slate" },
  // deleted = the user soft-deleted this intent (node and lineage are kept; see the delete_reason field for the reason).
  deleted: { tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  created: { tone: "slate" },
  queued: { tone: "amber" },
  running: { tone: "blue" },
  paused: { tone: "amber" },
  done: { tone: "green" },
  failed: { tone: "red" },
  timeout: { tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { tone: "rose" },
  high: { tone: "red" },
  medium: { tone: "amber" },
  low: { tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { tone: "amber" },
  in_progress: { tone: "blue" },
  confirmed: { tone: "red" },
  resolved: { tone: "green" },
  fixed: { tone: "green" },
  false_positive: { tone: "slate" },
  ignored: { tone: "neutral" },
  duplicate: { tone: "neutral" },
  risk_accepted: { tone: "violet" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { tone: "blue" },
  paused: { tone: "amber" },
  stalled: { tone: "red" },
  idle: { tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { tone: "blue" },
  met: { tone: "green" },
  abandoned: { tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { tone: "green" },
  block: { tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { tone: "slate" },
  confirmed: { tone: "green" },
  tombstoned: { tone: "neutral" },
};

// Notification delivery status. sending uses blue rather than amber: it is not "a problem"
// but "already claimed and being sent", which must be distinguishable from the waiting meaning of pending.
const delivery: Record<string, StatusMeta> = {
  pending: { tone: "amber" },
  sending: { tone: "blue" },
  sent: { tone: "green" },
  failed: { tone: "red" },
  skipped: { tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { tone: "neutral" };
}
