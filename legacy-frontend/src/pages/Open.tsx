import { useState } from "react";
import { useLoad, useSession, date, timeLeft } from "../lib/session";
import { fromB64Url, heirProof, newTransportKey, openVault } from "../lib/vault-crypto";
import { vaultPublicKey } from "../lib/vault-key";
import { ErrorLine, Pill } from "../components/ui";

/** The heir's page. No login: the link itself is the credential. */
export function Open({ id, secret }: { id: string; secret: string }) {
  const { actor, toast } = useSession();
  const valid = /^\d+$/.test(id) && /^[A-Za-z0-9_-]{43}$/.test(secret);
  const lookup = useLoad(async () => {
    if (!valid) throw new Error("This link is incomplete. Copy the whole link, including everything after #.");
    const proof = await heirProof(fromB64Url(secret));
    const r = await actor.heirLookup(BigInt(id), proof);
    if (r.__kind__ === "err") throw new Error(r.err);
    return { view: r.ok, proof };
  }, [id, secret]);
  const [text, setText] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function open() {
    if (!lookup.data) return;
    setBusy(true);
    setError(null);
    try {
      const publicKey = await vaultPublicKey(actor);
      const tsk = newTransportKey();
      const r = await actor.heirOpen(BigInt(id), lookup.data.proof, tsk.publicKeyBytes());
      if (r.__kind__ === "err") throw new Error(r.err);
      setText(await openVault(publicKey, tsk, r.ok, fromB64Url(secret)));
      lookup.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (lookup.error) {
    return (
      <div className="narrow">
        <h1 className="page-title">Vault link</h1>
        <ErrorLine error={lookup.error} />
      </div>
    );
  }
  if (!lookup.data) return <p className="muted">Checking the link…</p>;
  const v = lookup.data.view;

  return (
    <div className="narrow">
      <p className="eyebrow">For {v.heirName}</p>
      <h1 className="page-title">
        {v.title} {v.released ? <Pill tone="bad">Released</Pill> : <Pill tone="good">Locked</Pill>}
      </h1>

      {!v.released ? (
        <div className="card">
          <p>
            This vault is still locked. Its owner checks in regularly. It opens on <b>{date(v.deadline)}</b> (
            {timeLeft(v.deadline)}) only if they stop checking in.
          </p>
          <p className="muted small">Keep this link safe. You will need it then. Nobody can read the vault before that, not even with this link.</p>
        </div>
      ) : text == null ? (
        <div className="card">
          <p>Its owner has not checked in since the deadline ({date(v.deadline)}). You can open it now.</p>
          <p className="muted small">The text is decrypted in this browser only. This link can still be opened {v.opensLeft.toString()} times.</p>
          <ErrorLine error={error} />
          <button disabled={busy || v.opensLeft === 0n} onClick={open}>
            {busy ? "Opening…" : "Open the vault"}
          </button>
        </div>
      ) : (
        <div className="card">
          <pre className="secret">{text}</pre>
          <button className="small-btn" onClick={() => navigator.clipboard.writeText(text).then(() => toast("Copied."))}>
            Copy
          </button>
          <p className="muted small">Save what you need: this page does not keep it once closed.</p>
        </div>
      )}
    </div>
  );
}
