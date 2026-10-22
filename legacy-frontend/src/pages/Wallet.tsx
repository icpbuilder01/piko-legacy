import { useState } from "react";
import { Principal } from "@icp-sdk/core/principal";
import { getLedgerActor } from "../lib/actors";
import { formatPiko, parseAmount } from "../lib/format";
import { useLoad, useSession } from "../lib/session";
import { Amount, ErrorLine } from "../components/ui";

/** Receive PIKO to your Internet Identity principal, send it anywhere. */
export function Wallet() {
  const { identity, principal, login, toast } = useSession();
  const wallet = useLoad(async () => {
    if (!principal) return null;
    const ledger = getLedgerActor();
    const [balance, fee] = await Promise.all([ledger.icrc1_balance_of({ owner: principal }), ledger.icrc1_fee()]);
    return { balance, fee };
  }, [principal?.toText()]);
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!principal || !identity) {
    return (
      <div className="card narrow">
        <p>Log in to see your PIKO wallet.</p>
        <button onClick={login}>Log in</button>
      </div>
    );
  }
  const address = principal.toText();
  const data = wallet.data;

  async function send() {
    setError(null);
    const value = parseAmount(amount);
    if (value === null || value <= 0n) return setError("Enter a valid amount.");
    let dest: Principal;
    try {
      dest = Principal.fromText(to.trim());
    } catch {
      return setError("That is not a valid principal.");
    }
    if (dest.toText() === address) return setError("That is your own address.");
    if (data && value + data.fee > data.balance) return setError("Not enough PIKO (the ledger fee is added on top).");
    if (!window.confirm(`Send ${formatPiko(value)} PIKO to ${dest.toText()}? This cannot be undone.`)) return;
    setBusy(true);
    try {
      const r = await getLedgerActor(identity!).icrc1_transfer({ to: { owner: dest }, amount: value });
      if (r.__kind__ === "Err") {
        throw new Error(r.Err.__kind__ === "InsufficientFunds" ? "Not enough PIKO." : `Refused by the ledger: ${r.Err.__kind__}`);
      }
      toast(`Sent ${formatPiko(value)} PIKO (block ${r.Ok}).`);
      setTo("");
      setAmount("");
      wallet.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="narrow">
      <h1 className="page-title">PIKO wallet</h1>

      <div className="card wallet">
        <span className="field-label">Balance</span>
        <div className="big-amount">{data ? <Amount e8s={data.balance} /> : "…"}</div>
        <button className="ghost small-btn" onClick={wallet.reload}>
          Refresh
        </button>
        <ErrorLine error={wallet.error} />
      </div>

      <div className="card wallet">
        <span className="field-label">Receive: your PIKO address</span>
        <code className="address">{address}</code>
        <button
          className="small-btn"
          onClick={() => navigator.clipboard.writeText(address).then(() => toast("Address copied."))}
        >
          Copy address
        </button>
        <p className="small muted">
          Send PIKO here from any wallet or exchange (ICPSwap, OISY, NNS…). This address is yours on this site only: Internet
          Identity gives each site a different one.
        </p>
      </div>

      <div className="card form">
        <span className="field-label">Send PIKO</span>
        <label>
          To (principal)
          <input value={to} placeholder="xxxxx-xxxxx-…-cai or a wallet principal" onChange={(e) => setTo(e.target.value)} />
        </label>
        <label>
          Amount
          <div className="row">
            <input value={amount} inputMode="decimal" placeholder="0" onChange={(e) => setAmount(e.target.value)} />
            {data && data.balance > data.fee && (
              <button className="ghost small-btn" onClick={() => setAmount(formatPiko(data.balance - data.fee).replace(/,/g, ""))}>
                Max
              </button>
            )}
          </div>
        </label>
        <span className="small muted">Ledger fee: {data ? formatPiko(data.fee) : "0.0001"} PIKO, added on top.</span>
        <ErrorLine error={error} />
        <button disabled={busy || !to || !amount} onClick={send}>
          {busy ? "Sending…" : "Send"}
        </button>
      </div>
    </div>
  );
}
