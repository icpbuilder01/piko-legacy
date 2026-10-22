import { useEffect, useState } from "react";
import { Principal } from "@icp-sdk/core/principal";
import { ok, useLoad, useSession, intervalChoices } from "../lib/session";
import { getLedgerActor } from "../lib/actors";
import { legacyCanisterId } from "../lib/canister-env";
import { sealVault, toB64Url } from "../lib/vault-crypto";
import { vaultPublicKey } from "../lib/vault-key";
import { Amount, ErrorLine } from "../components/ui";

interface Made {
  id: bigint;
  title: string;
  links: { name: string; url: string }[];
}

export function NewVault() {
  const { actor, identity, principal, login, toast } = useSession();
  const config = useLoad(() => actor.getConfig(), [actor]);
  const balance = useLoad(
    async () => (principal ? getLedgerActor().icrc1_balance_of({ owner: principal }) : null),
    [principal?.toText()]
  );
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [heirs, setHeirs] = useState<string[]>([""]);
  const [interval, setIntervalSec] = useState<bigint>(90n * 86_400n);
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [made, setMade] = useState<Made | null>(null);

  if (!principal || !identity) {
    return (
      <div className="card narrow">
        <p>Log in to create a vault.</p>
        <button onClick={login}>Log in</button>
      </div>
    );
  }
  if (made) return <Links made={made} />;
  const c = config.data;
  if (!c) return config.error ? <ErrorLine error={config.error} /> : <p className="muted">Loading…</p>;

  const choices = intervalChoices(c.minIntervalSec);
  const names = heirs.map((h) => h.trim());
  const bytes = new TextEncoder().encode(text).length;
  const tooBig = bytes + 40 > Number(c.maxSecretBytes);
  const canSubmit = title.trim() && text.trim() && names.every(Boolean) && !tooBig && !step;
  const fee = c.feeE8s;

  async function submit() {
    setError(null);
    try {
      setStep("Encrypting in your browser…");
      const publicKey = await vaultPublicKey(actor);
      const sealed = await sealVault(publicKey, text, names);
      if (fee > 0n) {
        const ledger = getLedgerActor(identity!);
        const ledgerFee = await ledger.icrc1_fee();
        const have = await ledger.icrc1_balance_of({ owner: principal! });
        if (have < fee + 2n * ledgerFee) throw new Error("Not enough PIKO in your wallet for the fee.");
        setStep("Approving the PIKO fee…");
        const r = await ledger.icrc2_approve({
          spender: { owner: Principal.fromText(legacyCanisterId) },
          amount: fee + ledgerFee,
          expires_at: BigInt(Date.now() + 10 * 60_000) * 1_000_000n,
        });
        if (r.__kind__ === "Err") throw new Error(`Approval refused: ${JSON.stringify(r.Err, (_, v) => (typeof v === "bigint" ? v.toString() : v))}`);
      }
      setStep("Saving the vault…");
      const id = ok(
        await actor.createVault({
          title: title.trim(),
          ibeId: sealed.ibeId,
          ciphertext: sealed.ciphertext,
          intervalSec: interval,
          heirs: sealed.heirs.map((h) => ({ name: h.name, claimHash: h.claimHash, wrappedKey: h.wrappedKey })),
        })
      );
      const base = `${window.location.origin}${window.location.pathname}`;
      setMade({
        id,
        title: title.trim(),
        links: sealed.heirs.map((h) => ({ name: h.name, url: `${base}#/open/${id}/${toB64Url(h.secret)}` })),
      });
      setText("");
      toast("Vault created.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setStep(null);
    }
  }

  return (
    <div className="narrow">
      <a className="back" href="#/">
        ← My vaults
      </a>
      <h1 className="page-title">New vault</h1>

      <div className="card form">
        <label>
          Name (only you and your heirs see it)
          <input value={title} maxLength={80} placeholder="e.g. Crypto wallets" onChange={(e) => setTitle(e.target.value)} />
        </label>
        <label>
          Your secret
          <textarea
            rows={8}
            value={text}
            placeholder={"Seed phrase, passwords, where the papers are, a last message…"}
            onChange={(e) => setText(e.target.value)}
          />
          <span className={`small ${tooBig ? "st bad" : "muted"}`}>
            {bytes.toLocaleString()} / {(Number(c.maxSecretBytes) - 40).toLocaleString()} bytes. Encrypted in this browser
            before it is sent.
          </span>
        </label>

        <div className="field">
          <span className="field-label">Heirs (one private link each)</span>
          <span className="small muted">
            Just a first name, to tell the links apart. You will get a private link for each person, to send them however you
            like: email, paper, your notary. They don't need any account.
          </span>
          {heirs.map((h, i) => (
            <div className="row" key={i}>
              <input
                value={h}
                maxLength={60}
                placeholder={i === 0 ? "e.g. Marie" : "Name"}
                onChange={(e) => setHeirs(heirs.map((x, j) => (j === i ? e.target.value : x)))}
              />
              {heirs.length > 1 && (
                <button className="ghost small-btn" onClick={() => setHeirs(heirs.filter((_, j) => j !== i))}>
                  Remove
                </button>
              )}
            </div>
          ))}
          {heirs.length < Number(c.maxHeirs) && (
            <button className="ghost small-btn" onClick={() => setHeirs([...heirs, ""])}>
              + Add a heir
            </button>
          )}
        </div>

        <label>
          I will check in every
          <select value={interval.toString()} onChange={(e) => setIntervalSec(BigInt(e.target.value))}>
            {choices.map((x) => (
              <option key={x.sec.toString()} value={x.sec.toString()}>
                {x.label}
              </option>
            ))}
          </select>
          <span className="small muted">If you miss it, the vault opens for your heirs. You can change it later.</span>
        </label>

        <div className="pay">
          <span>
            One-time fee: <Amount e8s={fee} />
            <span className="muted small"> (shared between the PikoDice and PikoBlackjack bankrolls)</span>
          </span>
          {balance.data != null && (
            <span className="muted small">
              Wallet: <Amount e8s={balance.data} />
              {balance.data < fee + 20_000n && (
                <>
                  {" "}
                  · <a href="#/wallet">add PIKO</a>
                </>
              )}
            </span>
          )}
        </div>
        <ErrorLine error={error} />
        <button disabled={!canSubmit} onClick={submit}>
          {step ?? "Encrypt and create"}
        </button>
      </div>
    </div>
  );
}

/** A ready-to-send email for the heir, opened in the owner's own mail app. */
function heirMail(name: string, title: string, url: string): string {
  const body = [
    `Hi ${name},`,
    "",
    `I set up "${title}" for you on PIKO Legacy. It holds information you may need one day.`,
    "",
    "Please keep this link somewhere safe and do not share it:",
    url,
    "",
    "For now it opens nothing: it only unlocks if I stop checking in for a long time. If that happens, open the link and press \"Open the vault\". No account needed.",
  ].join("\n");
  return `mailto:?subject=${encodeURIComponent(`Something to keep safe: ${title}`)}&body=${encodeURIComponent(body)}`;
}

function Links({ made }: { made: Made }) {
  const { toast } = useSession();
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (saved) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [saved]);

  return (
    <div className="narrow">
      <h1 className="page-title">Save these links now</h1>
      <p className="notice warn">
        <b>They are shown only once.</b> Nobody can show them again, not even us. Each one is the only key to "{made.title}"
        for that person.
      </p>
      <div className="links">
        {made.links.map((l) => (
          <div className="card link" key={l.url}>
            <h3>For {l.name}</h3>
            <code>{l.url}</code>
            <div className="row wrap">
              <button
                className="small-btn"
                onClick={() => navigator.clipboard.writeText(l.url).then(() => toast(`Link for ${l.name} copied.`))}
              >
                Copy
              </button>
              <a className="button ghost small-btn" href={heirMail(l.name, made.title, l.url)}>
                Email it
              </a>
            </div>
          </div>
        ))}
      </div>
      <p className="muted">
        Give each link to its person, or keep it with your will. A link opens nothing before release, but anyone who has it
        can open the vault after release.
      </p>
      <p className="notice">
        <b>Safest: print it.</b> A paper link in an envelope (at home, with your notary) is harder to steal than an email. If
        you think a link leaked, delete the vault and make a new one: the old links stop working for good.
      </p>
      <label className="confirm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> I have saved every link
      </label>
      <a className={`button ${saved ? "" : "disabled"}`} href={saved ? "#/" : undefined}>
        Done
      </a>
    </div>
  );
}
