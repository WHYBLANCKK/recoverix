import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { PriorityLevel, RecoveryStatus } from "@/lib/types";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function PriorityBadge({ priority }: { priority: PriorityLevel }) {
  const styles: Record<PriorityLevel, string> = {
    CRITICAL: "bg-rose-50 text-rose-700 border-rose-300 font-semibold",
    HIGH: "bg-amber-50 text-amber-800 border-amber-300 font-semibold",
    MEDIUM: "bg-slate-100 text-slate-800 border-slate-300 font-semibold",
    LOW: "bg-slate-100 text-slate-700 border-slate-300 font-semibold",
  };

  return (
    <span className={cn("px-2.5 py-0.5 rounded-md text-xs font-medium border", styles[priority])}>
      {priority}
    </span>
  );
}

export function StatusBadge({ status }: { status: RecoveryStatus }) {
  const styles: Record<RecoveryStatus, string> = {
    FULLY_RECOVERED: "bg-emerald-50 text-emerald-700 border-emerald-300 font-semibold",
    PARTIALLY_RECOVERED: "bg-amber-50 text-amber-800 border-amber-300 font-semibold",
    CORRUPTED: "bg-rose-50 text-rose-700 border-rose-300 font-semibold",
    UNRECOVERABLE: "bg-slate-100 text-slate-700 border-slate-300 font-semibold",
  };

  const labels: Record<RecoveryStatus, string> = {
    FULLY_RECOVERED: "FULLY RECOVERED",
    PARTIALLY_RECOVERED: "PARTIAL",
    CORRUPTED: "CORRUPTED",
    UNRECOVERABLE: "UNRECOVERABLE",
  };

  return (
    <span className={cn("px-2.5 py-0.5 rounded-md text-xs font-medium border", styles[status])}>
      {labels[status]}
    </span>
  );
}
