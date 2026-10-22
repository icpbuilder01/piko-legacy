import type { ReactNode } from "react";
import { formatPiko } from "../lib/format";

export function Amount({ e8s }: { e8s: bigint }) {
  return (
    <span className="amount">
      {formatPiko(e8s)} <span className="unit">PIKO</span>
    </span>
  );
}

export function Pill({ children, tone }: { children: ReactNode; tone?: string }) {
  return <span className={`pill ${tone ?? ""}`}>{children}</span>;
}

export function ErrorLine({ error }: { error: string | null }) {
  return error ? <p className="error-line">{error}</p> : null;
}
