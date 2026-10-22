import { useState } from "react";
import { ok, useLoad, useSession, date, duration, timeLeft, intervalChoices } from "../lib/session";
import type { OwnerView } from "../bindings/legacy/legacy";
import { ErrorLine, Pill } from "../components/ui";

export function Vaults() {
  const { actor, toast } = useSession();
  const { data, error, reload } = useLoad(() => Promise.all([actor.myVaults(), actor.getConfig()]), [actor]);
  const [busy, setBusy] = useState(false);

  if (error) return <ErrorLine error={error} />;
  if (!data) return <p className="muted">Loading…</p>;
  const [vaults, config] = data;
  const active = vaults.filter((v) => !v.released).sort((a, b) => Number(a.deadline - b.deadline));
  const next = active[0];

  async function checkIn() {
    setBusy(true);
    try {
      const n = await actor.checkIn();
      toast(n === 1n ? "Checked in. Countdown restarted." : `Checked in. ${n} countdowns restarted.`);
      reload();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {active.length > 0 && (
        <section className="alive">
          <button className="big-btn" disabled={busy} onClick={checkIn}>
            {busy ? "Checking in…" : "I'm still here"}
          </button>
          <p>
            Next release in <b>{timeLeft(next.deadline)}</b> ({date(next.deadline)}) unless you check in.
          </p>
        </section>
      )}

      <div className="page-head">
        <h1>My vaults</h1>
        {vaults.length < Number(config.maxVaultsPerOwner) && (
          <a className="button" href="#/new">
            New vault
          </a>
        )}
      </div>

      {vaults.length === 0 ? (
        <div className="card empty-state">
          <p>You have no vault yet.</p>
          <a className="button" href="#/new">
            Create my first vault
          </a>
        </div>
      ) : (
        <div className="vaults">
          {vaults.map((v) => (
            <VaultCard key={v.id.toString()} v={v} minIntervalSec={config.minIntervalSec} onChange={reload} />
          ))}
        </div>
      )}
    </>
  );
}

function VaultCard({ v, minIntervalSec, onChange }: { v: OwnerView; minIntervalSec: bigint; onChange: () => void }) {
  const { actor, toast } = useSession();
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      onChange();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    } finally {
      setBusy(false);
    }
  }

  const choices = intervalChoices(minIntervalSec);
  if (!choices.some((c) => c.sec === v.intervalSec)) choices.push({ sec: v.intervalSec, label: duration(v.intervalSec) });

  return (
    <div className={`card vault ${v.released ? "released" : ""}`}>
      <div className="card-head">
        <h3>{v.title}</h3>
        {v.released ? <Pill tone="bad">Released</Pill> : <Pill tone="good">Locked</Pill>}
      </div>
      {v.released ? (
        <p className="muted">
          Released on {date(v.deadline)}. Your heirs can open it now. Delete it if this was a mistake (anything already opened
          stays opened).
        </p>
      ) : (
        <p>
          Releases <b>{date(v.deadline)}</b> <span className="muted">({timeLeft(v.deadline)} left)</span> unless you check in.
        </p>
      )}
      <p className="small muted">
        Heirs:{" "}
        {v.heirs.map((h, i) => (
          <span key={i}>
            {i > 0 && ", "}
            {h.name}
            {h.opens > 0n && ` (opened ${h.opens}×)`}
          </span>
        ))}{" "}
        · {v.secretBytes.toString()} bytes encrypted · created {date(v.createdAt)}
      </p>
      <div className="row wrap">
        {!v.released && (
          <label className="inline">
            Check in every
            <select
              value={v.intervalSec.toString()}
              disabled={busy}
              onChange={(e) =>
                run(() => actor.setInterval(v.id, BigInt(e.target.value)).then(ok), "Interval changed (and checked in).")
              }
            >
              {choices.map((c) => (
                <option key={c.sec.toString()} value={c.sec.toString()}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          className="danger small-btn"
          disabled={busy}
          onClick={() => {
            if (window.confirm(`Delete "${v.title}" for good? The heir links will stop working.`)) {
              run(() => actor.deleteVault(v.id).then(ok), "Vault deleted.");
            }
          }}
        >
          Delete
        </button>
      </div>
    </div>
  );
}
