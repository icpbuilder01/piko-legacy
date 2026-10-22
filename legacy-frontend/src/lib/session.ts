import { createContext, useContext, useEffect, useState } from "react";
import type { Identity } from "@icp-sdk/core/agent";
import type { Principal } from "@icp-sdk/core/principal";
import { getLegacyActor } from "./actors";

export type Legacy = ReturnType<typeof getLegacyActor>;

export interface Session {
  identity: Identity | null;
  principal: Principal | null;
  actor: Legacy; // anonymous when logged out
  login: () => Promise<void>;
  logout: () => Promise<void>;
  toast: (text: string, kind?: "ok" | "err") => void;
}

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) throw new Error("no session");
  return s;
}

/** Loads `fn` on mount and whenever `deps` change; `reload()` refetches. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    fn()
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e: unknown) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((t) => t + 1) };
}

/** Unwraps a canister `R` result: returns the ok value, or throws its error text. */
export function ok<T>(r: { __kind__: "ok"; ok: T } | { __kind__: "err"; err: string }): T {
  if (r.__kind__ === "err") throw new Error(r.err);
  return r.ok;
}

export function short(p: Principal | string): string {
  const t = typeof p === "string" ? p : p.toText();
  const parts = t.split("-");
  return parts.length > 2 ? `${parts[0]}…${parts[parts.length - 1]}` : t;
}

export function date(ns: bigint): string {
  return new Date(Number(ns / 1_000_000n)).toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const DAY = 86_400;

/** "30 days", "1 year", "5 minutes"... */
export function duration(sec: bigint | number): string {
  const s = Number(sec);
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  if (s % (365 * DAY) === 0) return plural(s / (365 * DAY), "year");
  if (s >= DAY) return plural(Math.round(s / DAY), "day");
  if (s >= 3600) return plural(Math.round(s / 3600), "hour");
  return plural(Math.round(s / 60), "minute");
}

/** Time left until `ns`, in words; "now" when past. */
export function timeLeft(ns: bigint): string {
  const sec = Math.floor((Number(ns / 1_000_000n) - Date.now()) / 1000);
  if (sec <= 0) return "now";
  if (sec < 3600) return `${Math.max(1, Math.round(sec / 60))} min`;
  if (sec < 2 * DAY) return `${Math.round(sec / 3600)} h`;
  return `${Math.floor(sec / DAY)} days`;
}

const DAY_N = 86_400n;

export function intervalChoices(minSec: bigint): { sec: bigint; label: string }[] {
  const list = [
    { sec: 30n * DAY_N, label: "month (30 days)" },
    { sec: 90n * DAY_N, label: "3 months" },
    { sec: 180n * DAY_N, label: "6 months" },
    { sec: 365n * DAY_N, label: "year" },
  ].filter((c) => c.sec >= minSec);
  // Local test networks allow very short intervals.
  if (minSec < 7n * DAY_N) list.unshift({ sec: minSec, label: `${duration(minSec)} (test)` });
  return list;
}

